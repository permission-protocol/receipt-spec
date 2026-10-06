// Reference implementation of the jcs_v3 signed decider proof (SPEC.md
// section 3.8). Dependency-free. Mirrors the hosted service's
// signing/decider-proof.ts (app repo, src/lib/permission-protocol-v1/), which
// is pure so that this file can follow it line for line.
//
// A jcs_v3 receipt whose decider stepped up at signing signs the evidence of
// that step-up as `deciderProof`, a JSON object inside the signed bytes:
//
//   webauthn  { method: "webauthn", credentialIdHash, challengeHash,
//               authenticatorDataHash, userVerified, rpId, origin,
//               reviewGeneration?, verifiedAt }
//   reauth    { method: "reauth", authTime, maxAgeMs, verifiedAt }
//
// Every listed key is required unless marked optional, and no other key is
// ever signed. The proof agrees with the signed `deciderAuthMethod` in both
// directions:
//
//   session_stepup_webauthn <=> method "webauthn"
//   session_reauth          <=> method "reauth"
//   any other value, or absent => no deciderProof
//
// deciderProofFromEvidence is the issuer's mint-side builder (generate-vectors
// uses it); checkDeciderProof is the check every verifier runs on the signed
// payload (SPEC.md section 6.7, step 2).

/** The proof method each step-up auth method requires; every other value requires none. */
export const DECIDER_PROOF_METHOD_BY_AUTH_METHOD = Object.freeze({
  session_stepup_webauthn: "webauthn",
  session_reauth: "reauth",
});

/** The proof method a signed deciderAuthMethod requires, or null when it requires none. */
export function requiredDeciderProofMethod(deciderAuthMethod) {
  if (typeof deciderAuthMethod !== "string") return null;
  return Object.prototype.hasOwnProperty.call(DECIDER_PROOF_METHOD_BY_AUTH_METHOD, deciderAuthMethod)
    ? DECIDER_PROOF_METHOD_BY_AUTH_METHOD[deciderAuthMethod]
    : null;
}

export class DeciderProofError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DeciderProofError";
    this.code = code;
  }
}

const SHA256_HEX = /^[a-f0-9]{64}$/;
const RP_ID = /^[A-Za-z0-9.-]{1,253}$/;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** An ISO 8601 instant exactly as Date.prototype.toISOString writes it. */
function isIsoInstant(value) {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

/** An http(s) origin exactly as the URL standard serializes it (no path, no trailing slash, default port omitted). */
function isCanonicalOrigin(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return (url.protocol === "https:" || url.protocol === "http:") && url.origin === value;
  } catch {
    return false;
  }
}

function invalid(message) {
  throw new DeciderProofError("DECIDER_PROOF_INVALID", message);
}

/**
 * The proof the issuer signs, built from the step-up evidence it stored for
 * the decision: only the listed keys are copied and every one is validated.
 * Stored evidence carries more (the authenticator's signature counter, the
 * bound request id and scope hash); none of it is signed.
 *
 * @throws DeciderProofError DECIDER_PROOF_INVALID
 */
export function deciderProofFromEvidence(evidence) {
  let value = evidence;
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch {
      invalid("The stored step-up evidence is not JSON");
    }
  }
  if (!isPlainObject(value)) invalid("The stored step-up evidence is not a JSON object");

  if (value.method === "webauthn") {
    for (const key of ["credentialIdHash", "challengeHash", "authenticatorDataHash"]) {
      if (typeof value[key] !== "string" || !SHA256_HEX.test(value[key])) {
        invalid(`webauthn evidence: ${key} is not a lowercase SHA-256 hex digest`);
      }
    }
    if (typeof value.userVerified !== "boolean") invalid("webauthn evidence: userVerified is not a boolean");
    if (typeof value.rpId !== "string" || !RP_ID.test(value.rpId)) invalid("webauthn evidence: rpId is not a host name");
    if (!isCanonicalOrigin(value.origin)) invalid("webauthn evidence: origin is not a canonical http(s) origin");
    if (!isIsoInstant(value.verifiedAt)) invalid("webauthn evidence: verifiedAt is not an ISO 8601 instant");
    const generation = value.reviewGeneration;
    if (generation !== undefined && !(Number.isSafeInteger(generation) && generation > 0)) {
      invalid("webauthn evidence: reviewGeneration is not a positive integer");
    }
    return {
      method: "webauthn",
      credentialIdHash: value.credentialIdHash,
      challengeHash: value.challengeHash,
      authenticatorDataHash: value.authenticatorDataHash,
      userVerified: value.userVerified,
      rpId: value.rpId,
      origin: value.origin,
      ...(generation !== undefined ? { reviewGeneration: generation } : {}),
      verifiedAt: value.verifiedAt,
    };
  }

  if (value.method === "reauth") {
    if (!isIsoInstant(value.authTime)) invalid("reauth evidence: authTime is not an ISO 8601 instant");
    if (!isIsoInstant(value.verifiedAt)) invalid("reauth evidence: verifiedAt is not an ISO 8601 instant");
    if (!Number.isSafeInteger(value.maxAgeMs) || value.maxAgeMs <= 0) invalid("reauth evidence: maxAgeMs is not a positive integer");
    // The step-up guard's own freshness rule: the re-authentication is at most
    // maxAgeMs old at the decision. A negative age is clock skew between the
    // issuer's instances, which the guard also accepts.
    if (Date.parse(value.verifiedAt) - Date.parse(value.authTime) > value.maxAgeMs) {
      invalid("reauth evidence: the re-login is older than maxAgeMs at verifiedAt");
    }
    return { method: "reauth", authTime: value.authTime, maxAgeMs: value.maxAgeMs, verifiedAt: value.verifiedAt };
  }

  invalid("The stored step-up evidence names no known method");
}

/**
 * The mint side, as the issuer's deciderProofForSigning: the proof a receipt
 * signs for a decider, or null when the decider did not step up. Fails closed
 * on any inconsistency with the auth method the same receipt signs.
 *
 * @throws DeciderProofError DECIDER_PROOF_MISSING | DECIDER_PROOF_UNEXPECTED |
 *   DECIDER_PROOF_INVALID | DECIDER_PROOF_METHOD_MISMATCH
 */
export function deciderProofForSigning(deciderAuthMethod, evidence) {
  const required = requiredDeciderProofMethod(deciderAuthMethod);
  const given = evidence !== null && evidence !== undefined && evidence !== "";
  if (!required) {
    if (given) throw new DeciderProofError("DECIDER_PROOF_UNEXPECTED", `Step-up evidence was given for a decider whose auth method is ${String(deciderAuthMethod)}`);
    return null;
  }
  if (!given) {
    throw new DeciderProofError("DECIDER_PROOF_MISSING", `The decider's auth method is ${String(deciderAuthMethod)} but no step-up evidence is stored for this decision`);
  }
  const proof = deciderProofFromEvidence(evidence);
  if (proof.method !== required) {
    throw new DeciderProofError("DECIDER_PROOF_METHOD_MISMATCH", `The decider's auth method is ${String(deciderAuthMethod)} but the stored evidence is ${proof.method}`);
  }
  return proof;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (!isPlainObject(value)) return value;
  const sorted = {};
  for (const key of Object.keys(value).sort()) sorted[key] = sortKeys(value[key]);
  return sorted;
}

/** The canonical text of a proof: keys sorted, no whitespace. The issuer stores this text. */
export function canonicalDeciderProofJson(proof) {
  return JSON.stringify(sortKeys(proof));
}

/**
 * The verify side (SPEC.md section 6.7, step 2), on the signed payload: the
 * signed deciderProof agrees with the signed deciderAuthMethod in both
 * directions and is a well-formed proof in its frozen shape. `deciderProof` is
 * the payload's value, undefined when the payload carries none. Null when it
 * holds, else { code, message }:
 * - DECIDER_PROOF_MISMATCH: a step-up auth method without a proof, a proof for
 *   any other auth method, or a proof of the other method;
 * - DECIDER_PROOF_INVALID: the proof is not an object, breaks a rule of its
 *   shape, or carries a key outside it.
 * Same results, in the same order, as the issuer's checkDeciderProofConsistency
 * over the stored proof text.
 */
export function checkDeciderProof(deciderAuthMethod, deciderProof) {
  const required = requiredDeciderProofMethod(deciderAuthMethod);
  const present = deciderProof !== undefined && deciderProof !== null;
  if (!required && !present) return null;
  if (!required) {
    return { code: "DECIDER_PROOF_MISMATCH", message: `a decider proof is signed for auth method ${String(deciderAuthMethod)}, which proves no step-up` };
  }
  if (!present) {
    return { code: "DECIDER_PROOF_MISMATCH", message: `the signed auth method ${String(deciderAuthMethod)} requires a signed decider proof and none is present` };
  }
  // The signed value is an object inside the bytes, never text to parse.
  if (!isPlainObject(deciderProof)) return { code: "DECIDER_PROOF_INVALID", message: "the signed deciderProof is not a JSON object" };
  let proof;
  try {
    proof = deciderProofFromEvidence(deciderProof);
  } catch (error) {
    return { code: "DECIDER_PROOF_INVALID", message: error instanceof Error ? error.message : String(error) };
  }
  if (canonicalDeciderProofJson(proof) !== canonicalDeciderProofJson(deciderProof)) {
    return { code: "DECIDER_PROOF_INVALID", message: "the signed decider proof carries keys or a form outside its frozen shape" };
  }
  if (proof.method !== required) {
    return { code: "DECIDER_PROOF_MISMATCH", message: `the signed auth method ${String(deciderAuthMethod)} requires a ${required} proof, not ${proof.method}` };
  }
  return null;
}
