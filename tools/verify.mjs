// Reference verifier for a receipt artifact (SPEC.md section 6) and an
// execution attestation (SPEC.md section 9). Dependency-free.
//
//   node tools/verify.mjs <artifact.json> <keys.json>
//   node tools/verify.mjs <artifact.json> <keys.json> --request <request.json> --salt <64 hex> [--summary <summary.txt>] [--binding <binding.json>]
//   node tools/verify.mjs <attestation.json> <keys.json> --receipt <receipt-artifact.json>
//
// All inputs are local files, so this runs with no network and no Permission
// Protocol service in the loop. --request and --salt (jcs_v3 receipts only)
// open the request commitment: the file is the exact request text the issuer
// committed to, byte for byte, and the salt its 32 bytes in hex (SPEC.md
// section 6.7). --summary (with them) names a file holding, as exact text, the
// summary the issuer states for the receipt (its owner artifact's `summary`):
// it must be the summary the commitment binds under receiptSummary. --binding
// (with them) names a JSON file of the values the issuer states for the
// receipt's companyId, idemKey and inputHash (its owner artifact's company_id,
// idem_key and input_hash), any subset: each must equal the one the commitment
// binds under receiptBinding. The summary file is read as exact text less one
// trailing line ending ("\n" or "\r\n"), so a file `echo` or an editor wrote
// states the summary without it; a summary that itself ends in a line ending
// needs one more in the file. Exit codes: 0 verified, 1 signature invalid, 2
// key not found or revoked, 3 malformed (including a jcs_v3 payload whose
// receiptVersion is not 3, whose signed requestCommitment is missing or not
// sha256:<64 lowercase hex> (REQUEST_COMMITMENT_MALFORMED), or whose
// publicProjectionJson is not JSON text of an object naming a tag), 4 payload
// does not match its hash or its own canonicalization, 8 unverifiable here,
// not tampered: a canonicalization or projection tag this verifier does not
// support, 9 policy failure: the signature is valid but the signed
// record breaks a rule of its own format (a projection outside its
// allowlist, or a decider proof that is malformed or disagrees with the
// signed deciderAuthMethod), 10 the supplied request, salt, summary and
// binding do not open the commitment: the commitment does not reproduce, the
// summary or binding is not the committed one, or the projection does not
// rebuild. Attestations add 5, 6 and 7 (section 9.5).
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  CanonicalizationUnsupportedError,
  RECEIPT_BINDING_FIELDS,
  RECEIPT_BINDING_REQUEST_KEY,
  RECEIPT_SUMMARY_REQUEST_KEY,
  attestationBytes,
  canonicalBytes,
  receiptBindingProblem,
  requestCommitment,
  signingDigest,
} from "./canonicalize.mjs";
import { checkDeciderProof } from "./decider-proof.mjs";
import { buildPublicProjection, checkPublicProjection, readProjectionTag } from "./public-projection.mjs";

/**
 * Exit code per failure code (SPEC.md section 6.2). Receipts: 1 to 4 and 8 to
 * 10; attestations add 5 to 7 (section 9.5). One meaning per code, and one
 * class per exit code: 3 malformed (the signed bytes are not a well-formed
 * receipt), 8 unverifiable here (never a pass, never tampered: a version
 * this verifier does not implement, or opening material it was not given), 9
 * the issuer signed what its own format forbids, 10 the private record
 * supplied with the receipt (request, salt, summary, binding) is not the one
 * the signature committed to.
 */
export const EXIT_CODES = Object.freeze({
  SIGNATURE_INVALID: 1,
  KEY_NOT_FOUND: 2,
  KEY_REVOKED: 2,
  MALFORMED: 3,
  PAYLOAD_HASH_MISMATCH: 4,
  CANONICAL_MISMATCH: 4,
  ATTESTATION_UNSIGNED: 5,
  PAYLOAD_WITHHELD: 6,
  ATTESTATION_INCONSISTENT: 7,
  REQUEST_COMMITMENT_MALFORMED: 3,
  CANONICALIZATION_UNSUPPORTED: 8,
  PROJECTION_UNSUPPORTED: 8,
  REQUEST_COMMITMENT_UNAVAILABLE: 8,
  PROJECTION_NOT_ALLOWED: 9,
  DECIDER_PROOF_MISMATCH: 9,
  DECIDER_PROOF_INVALID: 9,
  REQUEST_COMMITMENT_MISMATCH: 10,
  COMMITTED_SUMMARY_MISMATCH: 10,
  RECEIPT_BINDING_MISMATCH: 10,
  PUBLIC_PROJECTION_MISMATCH: 10,
});

/** "sha256:" plus 64 lowercase hex: the only form a signed requestCommitment takes (SPEC.md section 3.5). */
const REQUEST_COMMITMENT_PATTERN = /^sha256:[a-f0-9]{64}$/;

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Build a public key object from the key set's raw 32-byte base64 value. */
export function publicKeyFromRaw(publicKeyB64) {
  const raw = Buffer.from(publicKeyB64, "base64");
  if (raw.length !== 32) throw new Error(`public key must be 32 bytes, got ${raw.length}`);
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

/**
 * Verify an artifact envelope against a key set. Returns { ok: true, payload }
 * or { ok: false, code, message }. Never throws on bad input.
 *
 * The key and the signature are checked before the canonicalization (SPEC.md
 * section 6.2): only a verified signature over an unknown canonicalization is
 * "unsupported"; a bad one fails as a bad signature whatever the bytes claim.
 *
 * jcs_v3 receipts also get the well-formedness check, the projection check,
 * the decider proof check and the commitment form check (SPEC.md section 6.7,
 * steps 1 and 2) and, when options.opening = { requestJson, salt, summary?,
 * binding? } is given, the commitment opening (step 3); the result then
 * carries `projection`, `projectionTag`, `commitmentOpened` and, once opened,
 * `committedSummary` and `committedBinding`. `opening.summary` is the summary
 * the issuer states for the receipt: a string, null for "none", or undefined
 * when the caller holds none (then only the committed one is reported).
 * `opening.binding` is the companyId, idemKey and inputHash the issuer states
 * for it, any subset, or undefined when the caller holds none.
 */
export function verifyArtifact(envelope, keySet, options = {}) {
  const artifact = envelope?.artifact;
  if (!artifact || typeof artifact !== "object") return fail(3, "MALFORMED", "no artifact object");
  for (const field of ["receipt_id", "key_id", "alg", "signed_payload_hash", "signature_b64", "payload_bytes_b64"]) {
    if (typeof artifact[field] !== "string") return fail(3, "MALFORMED", `artifact.${field} missing`);
  }
  if (artifact.alg !== "ed25519") return fail(3, "MALFORMED", `unsupported alg ${artifact.alg}`);

  const payloadBytes = Buffer.from(artifact.payload_bytes_b64, "base64");
  const digest = signingDigest(payloadBytes);
  if (digest.toString("hex") !== artifact.signed_payload_hash) {
    return fail(4, "PAYLOAD_HASH_MISMATCH", "sha256(payload_bytes) does not equal signed_payload_hash");
  }

  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return fail(3, "MALFORMED", "payload bytes are not JSON");
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return fail(3, "MALFORMED", "payload bytes are not a JSON object");
  if (payload.signatureKeyId !== artifact.key_id) {
    return fail(3, "MALFORMED", "artifact.key_id disagrees with the signed signatureKeyId");
  }

  // The key and the signature come first: they do not depend on the
  // canonicalization, and nothing about the bytes is reported before the
  // signature over them verifies.
  const key = (keySet?.keys ?? []).find((candidate) => candidate.key_id === artifact.key_id);
  if (!key) return fail(2, "KEY_NOT_FOUND", `key ${artifact.key_id} is not in the key set`);
  if (key.alg !== "ed25519") return fail(2, "KEY_NOT_FOUND", `key ${artifact.key_id} is not ed25519`);
  if (key.status === "revoked") return fail(2, "KEY_REVOKED", `key ${artifact.key_id} is revoked`);

  let publicKey;
  try {
    publicKey = publicKeyFromRaw(key.public_key_b64);
  } catch (error) {
    return fail(3, "MALFORMED", error.message);
  }
  const signature = Buffer.from(artifact.signature_b64, "base64");
  if (signature.length !== 64) return fail(3, "MALFORMED", "signature is not 64 bytes");
  if (!verify(null, digest, publicKey, signature)) return fail(1, "SIGNATURE_INVALID", "Ed25519 signature does not verify over the digest");

  // The bytes must be the canonical form of the object they encode. A payload
  // that re-canonicalizes to different bytes was not produced by this spec.
  let recanonical;
  try {
    recanonical = canonicalBytes(payload, payload.canonicalization);
  } catch (error) {
    // A version this verifier does not define is unverifiable here, not
    // tampered, and is never re-canonicalized under another version's list.
    if (error instanceof CanonicalizationUnsupportedError && typeof payload.canonicalization === "string") {
      return fail(8, "CANONICALIZATION_UNSUPPORTED", `canonicalization ${payload.canonicalization} is not supported by this verifier; the signature verifies, and the receipt is unverifiable here, not tampered`);
    }
    return fail(3, "MALFORMED", error.message);
  }
  if (!recanonical.equals(payloadBytes)) {
    return fail(4, "CANONICAL_MISMATCH", "payload bytes are not the canonical encoding of the payload");
  }

  const now = options.now ?? new Date();
  const expired = typeof payload.expiresAt === "string" && new Date(payload.expiresAt) < now;
  const result = { ok: true, payload, expired, decision: payload.status, decider: payload.deciderDisplay ?? payload.deciderId ?? null };
  if (payload.canonicalization !== "jcs_v3") {
    if (options.opening) {
      return fail(64, "OPENING_NOT_APPLICABLE", `a request opening applies to jcs_v3 receipts; this one is ${payload.canonicalization} and signs its request in the bytes`);
    }
    return result;
  }

  // jcs_v3, section 6.7. Signed and intact. A jcs_v3 payload is receipt
  // version 3, its signed requestCommitment is sha256:<64 lowercase hex>, and
  // its projection is JSON text of an object naming a tag (malformed
  // otherwise: no issuer's mint produces anything else). Step 1: the
  // projection must be one the build rule could have produced for its tag (a
  // policy failure if not: the signature is valid, the issuer published a
  // field it must not have). Step 2: the signed decider proof must agree with
  // the signed auth method and keep its frozen shape (a policy failure if
  // not).
  if (payload.receiptVersion !== 3) {
    return fail(3, "MALFORMED", `a jcs_v3 payload is receiptVersion 3, not ${JSON.stringify(payload.receiptVersion ?? null)}`);
  }
  if (typeof payload.requestCommitment !== "string" || !REQUEST_COMMITMENT_PATTERN.test(payload.requestCommitment)) {
    return fail(3, "REQUEST_COMMITMENT_MALFORMED", "the signed requestCommitment is missing or is not sha256:<64 lowercase hex>");
  }
  const checked = checkPublicProjection(payload.publicProjectionJson);
  if (!checked.ok) return fail(EXIT_CODES[checked.code], checked.code, checked.message);
  const proofProblem = checkDeciderProof(payload.deciderAuthMethod, payload.deciderProof);
  if (proofProblem) return fail(EXIT_CODES[proofProblem.code], proofProblem.code, proofProblem.message);
  const v3 = { ...result, projection: checked.projection, projectionTag: checked.tag, deciderProof: payload.deciderProof ?? null, commitmentOpened: false };
  if (!options.opening) return v3;
  // Step 3, the holder of the request and its salt.
  const { requestJson, salt, summary, binding } = options.opening;
  const problem = openRequestCommitment(payload, requestJson, salt, { summary, binding });
  if (problem) return fail(EXIT_CODES[problem.code], problem.code, problem.message);
  const committed = JSON.parse(requestJson);
  return { ...v3, commitmentOpened: true, committedSummary: committedSummaryOf(requestJson), committedBinding: { ...committed[RECEIPT_BINDING_REQUEST_KEY] } };
}

/** The summary an opened request commits (receiptSummary), or null when it commits none. */
export function committedSummaryOf(requestJson) {
  const request = JSON.parse(requestJson);
  return Object.prototype.hasOwnProperty.call(request, RECEIPT_SUMMARY_REQUEST_KEY) ? request[RECEIPT_SUMMARY_REQUEST_KEY] : null;
}

/**
 * Open a jcs_v3 receipt's request commitment (SPEC.md section 6.7, step 3):
 * the supplied request text and salt must reproduce the signed
 * requestCommitment; the opened request must commit the summary as the
 * issuer's mint does (receiptSummary, a string, present exactly when there is
 * a summary) and, when the caller states a summary (options.summary: a string,
 * or null for none), commit exactly that one; it must commit the receipt's
 * binding as the mint does (receiptBinding, an object with exactly companyId,
 * idemKey and inputHash, each a string or null) and, when the caller states
 * any of those values (options.binding), commit exactly those; and the
 * projection rebuilt from the request under the signed tag must equal the
 * signed publicProjectionJson byte for byte. Null when all hold, else
 * { code, message }. Same checks, in the same order, as the issuer's
 * checkReceiptV3RequestBinding (app repo, signing/receipt-v3.ts) up to its
 * decider proof check, which every verifier runs on the signed payload
 * instead (step 2).
 */
export function openRequestCommitment(payload, requestJson, salt, options = {}) {
  // A signed commitment that is not sha256:<64 lowercase hex> is a malformed
  // receipt; REQUEST_COMMITMENT_UNAVAILABLE means only that the request text
  // or the salt needed to open a well-formed one is missing.
  if (typeof payload?.requestCommitment !== "string" || !REQUEST_COMMITMENT_PATTERN.test(payload.requestCommitment)) {
    return { code: "REQUEST_COMMITMENT_MALFORMED", message: "the signed requestCommitment is missing or is not sha256:<64 lowercase hex>" };
  }
  if (typeof requestJson !== "string" || salt == null || salt.length === 0) {
    return { code: "REQUEST_COMMITMENT_UNAVAILABLE", message: "an opening needs the exact request text and its salt" };
  }
  if (salt.length !== 32 || requestCommitment(salt, requestJson) !== payload.requestCommitment) {
    return { code: "REQUEST_COMMITMENT_MISMATCH", message: "the supplied request and salt do not open the signed requestCommitment" };
  }
  // The committed summary (section 3.5): the issuer's mint writes receiptSummary
  // only as a string. When the caller states a summary, it must be that one.
  let request = null;
  try {
    request = JSON.parse(requestJson);
  } catch {
    // Not JSON: no committed summary or binding; the binding check below fails.
  }
  const isObject = request !== null && typeof request === "object" && !Array.isArray(request);
  const hasCommitted = isObject && Object.prototype.hasOwnProperty.call(request, RECEIPT_SUMMARY_REQUEST_KEY);
  const committed = hasCommitted ? request[RECEIPT_SUMMARY_REQUEST_KEY] : undefined;
  if (hasCommitted && typeof committed !== "string") {
    return { code: "COMMITTED_SUMMARY_MISMATCH", message: `the committed ${RECEIPT_SUMMARY_REQUEST_KEY} is not a string; the issuer commits a summary only as text` };
  }
  if (options.summary !== undefined) {
    const stated = options.summary;
    const holds = hasCommitted ? committed === stated : stated === null;
    if (!holds) {
      return {
        code: "COMMITTED_SUMMARY_MISMATCH",
        message: hasCommitted
          ? `the stated summary is not the summary the commitment binds under ${RECEIPT_SUMMARY_REQUEST_KEY}`
          : `a summary is stated, but the committed request binds none (no ${RECEIPT_SUMMARY_REQUEST_KEY})`,
      };
    }
  }
  // The committed binding (section 3.5): always present on a jcs_v3 receipt,
  // exactly as the mint writes it. When the caller states any of its values,
  // each stated one must be the committed one.
  if (!isObject || !Object.prototype.hasOwnProperty.call(request, RECEIPT_BINDING_REQUEST_KEY)) {
    return { code: "RECEIPT_BINDING_MISMATCH", message: `the committed request carries no ${RECEIPT_BINDING_REQUEST_KEY}; every jcs_v3 receipt's mint commits one` };
  }
  const binding = request[RECEIPT_BINDING_REQUEST_KEY];
  const bindingProblem = receiptBindingProblem(binding);
  if (bindingProblem) {
    return { code: "RECEIPT_BINDING_MISMATCH", message: `the committed ${bindingProblem}; the issuer's mint writes exactly companyId, idemKey and inputHash, each a string or null` };
  }
  if (options.binding !== undefined) {
    const stated = options.binding;
    if (stated === null || typeof stated !== "object" || Array.isArray(stated)) {
      return { code: "RECEIPT_BINDING_MISMATCH", message: "the stated binding is not an object of companyId, idemKey and inputHash" };
    }
    for (const field of Object.keys(stated)) {
      if (!RECEIPT_BINDING_FIELDS.includes(field)) {
        return { code: "RECEIPT_BINDING_MISMATCH", message: `the stated binding names ${JSON.stringify(field)}, which receiptBinding does not carry` };
      }
      if (stated[field] !== binding[field]) {
        return { code: "RECEIPT_BINDING_MISMATCH", message: `the stated ${field} is not the ${field} the commitment binds under ${RECEIPT_BINDING_REQUEST_KEY}` };
      }
    }
  }
  const tag = typeof payload.publicProjectionJson === "string" ? readProjectionTag(payload.publicProjectionJson) : null;
  if (!tag) return { code: "PROJECTION_UNSUPPORTED", message: "the signed publicProjectionJson names no projection tag this verifier supports" };
  let rebuilt = null;
  try {
    rebuilt = buildPublicProjection(tag, requestJson);
  } catch {
    rebuilt = null;
  }
  if (rebuilt !== payload.publicProjectionJson) {
    return { code: "PUBLIC_PROJECTION_MISMATCH", message: `the ${tag} projection rebuilt from the committed request differs from the signed publicProjectionJson` };
  }
  return null;
}

const OUTCOMES = new Set(["succeeded", "failed", "unknown"]);
const OUTPUT_HASH = /^sha256:[0-9a-f]{64}$/;

/** An ISO 8601 instant exactly as the issuer writes one: YYYY-MM-DDTHH:mm:ss.sssZ, a real calendar date. */
function isIsoInstant(value) {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

/**
 * Verify an execution attestation envelope (SPEC.md section 9.5) against a key
 * set and the receipt artifact it attests. The receipt is verified first; the
 * attestation must name that receipt, which must be APPROVED. Returns
 * { ok: true, attestation, receipt } or { ok: false, code, message }.
 */
export function verifyAttestationArtifact(envelope, keySet, receiptEnvelope, options = {}) {
  const artifact = envelope?.attestation_artifact;
  if (!artifact || typeof artifact !== "object") return fail(3, "MALFORMED", "no attestation_artifact object");
  if (artifact.signed === false) {
    return fail(5, "ATTESTATION_UNSIGNED", "the issuer recorded this outcome without a signature (signing_failed); it proves nothing");
  }
  if (artifact.payload_withheld === true) {
    return fail(6, "PAYLOAD_WITHHELD", "the attestation payload is withheld on this surface; fetch the owner's artifact to verify it");
  }
  for (const field of ["approval_receipt_id", "key_id", "alg", "signed_payload_hash", "signature_b64", "payload_bytes_b64"]) {
    if (typeof artifact[field] !== "string") return fail(3, "MALFORMED", `attestation_artifact.${field} missing`);
  }
  if (artifact.alg !== "ed25519") return fail(3, "MALFORMED", `unsupported alg ${artifact.alg}`);

  const receipt = verifyArtifact(receiptEnvelope, keySet, options);
  if (!receipt.ok) return fail(receipt.exitCode, `RECEIPT_${receipt.code}`, `the attested receipt does not verify: ${receipt.message}`);
  if (receipt.payload.id !== artifact.approval_receipt_id) {
    return fail(3, "RECEIPT_MISMATCH", "approval_receipt_id does not name the receipt supplied");
  }
  if (receipt.payload.status !== "APPROVED") {
    return fail(3, "RECEIPT_NOT_APPROVED", "only an APPROVED authorization can have an execution attestation");
  }

  const payloadBytes = Buffer.from(artifact.payload_bytes_b64, "base64");
  const digest = signingDigest(payloadBytes);
  if (digest.toString("hex") !== artifact.signed_payload_hash) {
    return fail(4, "PAYLOAD_HASH_MISMATCH", "sha256(payload_bytes) does not equal signed_payload_hash");
  }
  let attestation;
  try {
    attestation = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return fail(3, "MALFORMED", "payload bytes are not JSON");
  }
  if (attestation.signatureKeyId !== artifact.key_id) {
    return fail(3, "MALFORMED", "attestation_artifact.key_id disagrees with the signed signatureKeyId");
  }
  let recanonical;
  try {
    recanonical = attestationBytes(attestation);
  } catch (error) {
    return fail(3, "MALFORMED", error.message);
  }
  if (!recanonical.equals(payloadBytes)) {
    return fail(4, "CANONICAL_MISMATCH", "payload bytes are not the attest_v1 encoding of the payload");
  }

  const key = (keySet?.keys ?? []).find((candidate) => candidate.key_id === artifact.key_id);
  if (!key) return fail(2, "KEY_NOT_FOUND", `key ${artifact.key_id} is not in the key set`);
  if (key.alg !== "ed25519") return fail(2, "KEY_NOT_FOUND", `key ${artifact.key_id} is not ed25519`);
  if (key.status === "revoked") return fail(2, "KEY_REVOKED", `key ${artifact.key_id} is revoked`);
  let publicKey;
  try {
    publicKey = publicKeyFromRaw(key.public_key_b64);
  } catch (error) {
    return fail(3, "MALFORMED", error.message);
  }
  const signature = Buffer.from(artifact.signature_b64, "base64");
  if (signature.length !== 64) return fail(3, "MALFORMED", "signature is not 64 bytes");
  if (!verify(null, digest, publicKey, signature)) return fail(1, "SIGNATURE_INVALID", "Ed25519 signature does not verify over the digest");

  // Signed, intact, and bound to the receipt. Now the claims must agree with
  // each other (section 9.2); a contradiction is a policy failure, not tampering.
  if (attestation.approvalReceiptId !== artifact.approval_receipt_id) {
    return fail(3, "MALFORMED", "the signed approvalReceiptId disagrees with the envelope");
  }
  const problem = attestationClaimProblem(attestation);
  if (problem) return fail(7, "ATTESTATION_INCONSISTENT", problem);
  return { ok: true, attestation, receipt: receipt.payload, outcome: attestation.outcome };
}

/**
 * Section 9.2 consistency rules; null when the claims agree. startedAt and
 * finishedAt, when present, are ISO 8601 instants exactly as the issuer
 * writes them (schema/attestation-v1.json), and outputHash is the string
 * sha256:<64 hex>; nothing is coerced.
 */
export function attestationClaimProblem(attestation) {
  if (!OUTCOMES.has(attestation.outcome)) return `unknown outcome ${attestation.outcome}`;
  if (attestation.outputHash !== undefined && (typeof attestation.outputHash !== "string" || !OUTPUT_HASH.test(attestation.outputHash))) {
    return "outputHash is not sha256:<64 hex>";
  }
  for (const field of ["startedAt", "finishedAt"]) {
    if (attestation[field] !== undefined && !isIsoInstant(attestation[field])) return `${field} is not an ISO 8601 instant (YYYY-MM-DDTHH:mm:ss.sssZ)`;
  }
  if (attestation.outcome === "unknown") {
    if (attestation.finishedAt !== undefined) return "an unknown outcome has no finish time";
    if (attestation.outputHash !== undefined) return "an unknown outcome has no output";
    return null;
  }
  if (attestation.startedAt === undefined || attestation.finishedAt === undefined) {
    return `a ${attestation.outcome} outcome has a start and a finish time`;
  }
  if (Date.parse(attestation.finishedAt) < Date.parse(attestation.startedAt)) return "finishedAt is before startedAt";
  return null;
}

/**
 * A stated summary read from a file (--summary): the exact text, less one
 * trailing line ending ("\n" or "\r\n"). Nothing else is trimmed.
 */
export function summaryFromFile(text) {
  if (text.endsWith("\r\n")) return text.slice(0, -2);
  if (text.endsWith("\n")) return text.slice(0, -1);
  return text;
}

function fail(exitCode, code, message) {
  return { ok: false, exitCode, code, message };
}

function usage(message) {
  if (message) console.error(message);
  console.error("usage: node tools/verify.mjs <artifact.json> <keys.json> [--request <request.json> --salt <64 hex> [--summary <summary.txt>] [--binding <binding.json>]]");
  console.error("       node tools/verify.mjs <attestation.json> <keys.json> --receipt <receipt-artifact.json>");
  process.exit(64);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const flags = {};
  const positional = [];
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index].match(/^--(receipt|request|salt|summary|binding)$/);
    if (!flag) {
      positional.push(args[index]);
      continue;
    }
    if (args[index + 1] === undefined) usage(`${args[index]} needs a value`);
    flags[flag[1]] = args[(index += 1)];
  }
  const receiptPath = flags.receipt ?? null;
  const [artifactPath, keysPath] = positional;
  if (!artifactPath || !keysPath || positional.length > 2) usage();
  if ((flags.request === undefined) !== (flags.salt === undefined)) usage("--request and --salt go together: the commitment opens with both");
  if (flags.salt !== undefined && !/^[0-9a-fA-F]{64}$/.test(flags.salt)) usage("--salt is the 32-byte salt as 64 hex characters");
  if (flags.summary !== undefined && flags.request === undefined) usage("--summary is checked against the opened commitment: add --request and --salt");
  if (flags.binding !== undefined && flags.request === undefined) usage("--binding is checked against the opened commitment: add --request and --salt");
  const opening =
    flags.request === undefined
      ? undefined
      : {
          requestJson: readFileSync(flags.request, "utf8"),
          salt: Buffer.from(flags.salt, "hex"),
          summary: flags.summary === undefined ? undefined : summaryFromFile(readFileSync(flags.summary, "utf8")),
          binding: flags.binding === undefined ? undefined : JSON.parse(readFileSync(flags.binding, "utf8")),
        };
  const envelope = JSON.parse(readFileSync(artifactPath, "utf8"));
  const keySet = JSON.parse(readFileSync(keysPath, "utf8"));
  if (envelope.attestation_artifact && !envelope.artifact) {
    if (opening) usage("--request, --salt, --summary and --binding open a jcs_v3 receipt's commitment, not an attestation");
    if (!receiptPath) {
      console.error("an attestation is verified with the receipt it attests: add --receipt <receipt-artifact.json>");
      process.exit(64);
    }
    const result = verifyAttestationArtifact(envelope, keySet, JSON.parse(readFileSync(receiptPath, "utf8")));
    if (!result.ok) {
      console.error(`FAILED ${result.code}: ${result.message}`);
      process.exit(result.exitCode);
    }
    console.log(`VERIFIED attestation for ${result.receipt.id}`);
    console.log(`outcome: ${result.outcome}${result.attestation.finishedAt ? ` (finished ${result.attestation.finishedAt})` : ""}`);
    console.log(`authorized by: ${result.receipt.deciderDisplay ?? result.receipt.deciderId} (${result.receipt.deciderId})`);
    process.exit(0);
  }
  const result = verifyArtifact(envelope, keySet, { opening });
  if (!result.ok) {
    console.error(`FAILED ${result.code}: ${result.message}`);
    process.exit(result.exitCode);
  }
  console.log(`VERIFIED ${result.payload.id}`);
  console.log(`decision: ${result.decision}${result.expired ? " (expired for redemption; signature still valid)" : ""}`);
  console.log(`decider: ${result.decider} (${result.payload.deciderId})`);
  console.log(`policy: ${result.payload.policyVersion ?? "none"}`);
  if (result.projectionTag) {
    console.log(`projection: ${result.projectionTag}, within its allowlist`);
    console.log(
      result.deciderProof
        ? `decider proof: ${result.deciderProof.method}, consistent with ${result.payload.deciderAuthMethod}`
        : `decider proof: none (${result.payload.deciderAuthMethod ?? "no auth method"} proves no step-up)`
    );
    if (result.commitmentOpened) {
      console.log(`commitment: ${result.payload.requestCommitment} opened with the supplied request and salt; the projection rebuilds from it byte for byte`);
      const summaryText = result.committedSummary === null ? "none" : JSON.stringify(result.committedSummary);
      console.log(`summary: ${summaryText} (committed, not in the signed bytes${opening.summary === undefined ? "; not compared with a stated summary" : "; equals the stated summary"})`);
      const bound = result.committedBinding;
      console.log(
        `binding: companyId ${JSON.stringify(bound.companyId)}, idemKey ${JSON.stringify(bound.idemKey)}, inputHash ${JSON.stringify(bound.inputHash)} (committed, not in the signed bytes${opening.binding === undefined ? "; not compared with stated values" : "; equals the stated values"})`
      );
    } else {
      console.log(`commitment: ${result.payload.requestCommitment} (not opened; the request holder opens it with --request <file> --salt <hex>)`);
    }
  }
}
