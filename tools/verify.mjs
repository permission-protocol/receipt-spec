// Reference verifier for a receipt artifact (SPEC.md section 6) and an
// execution attestation (SPEC.md section 9). Dependency-free.
//
//   node tools/verify.mjs <artifact.json> <keys.json>
//   node tools/verify.mjs <artifact.json> <keys.json> --request <request.json> --salt <64 hex>
//   node tools/verify.mjs <attestation.json> <keys.json> --receipt <receipt-artifact.json>
//
// All inputs are local files, so this runs with no network and no Permission
// Protocol service in the loop. --request and --salt (jcs_v3 receipts only)
// open the request commitment: the file is the exact request text the issuer
// committed to, byte for byte, and the salt its 32 bytes in hex (SPEC.md
// section 6.7). Exit codes: 0 verified, 1 signature invalid, 2 key not found
// or revoked, 3 malformed, 4 payload does not match its hash or its own
// canonicalization, 8 canonicalization or projection tag not supported by this
// verifier (unverifiable here, not tampered), 9 the signed projection breaks
// its allowlist (policy failure; the signature is valid), 10 the supplied
// request and salt do not open the commitment or do not rebuild the
// projection. Attestations add 5, 6 and 7 (section 9.5).
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { CanonicalizationUnsupportedError, attestationBytes, canonicalBytes, requestCommitment, signingDigest } from "./canonicalize.mjs";
import { buildPublicProjection, checkPublicProjection, readProjectionTag } from "./public-projection.mjs";

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
 * jcs_v3 receipts also get the projection check (SPEC.md section 6.7) and, when
 * options.opening = { requestJson, salt } is given, the commitment opening;
 * the result then carries `projection`, `projectionTag` and `commitmentOpened`.
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
  if (payload.signatureKeyId !== artifact.key_id) {
    return fail(3, "MALFORMED", "artifact.key_id disagrees with the signed signatureKeyId");
  }
  // The bytes must be the canonical form of the object they encode. A payload
  // that re-canonicalizes to different bytes was not produced by this spec.
  let recanonical;
  try {
    recanonical = canonicalBytes(payload, payload.canonicalization);
  } catch (error) {
    // A version this verifier does not define is unverifiable here, not
    // tampered, and is never re-canonicalized under another version's list.
    if (error instanceof CanonicalizationUnsupportedError && typeof payload.canonicalization === "string") {
      return fail(8, "CANONICALIZATION_UNSUPPORTED", `canonicalization ${payload.canonicalization} is not supported by this verifier; the receipt is unverifiable here, not tampered`);
    }
    return fail(3, "MALFORMED", error.message);
  }
  if (!recanonical.equals(payloadBytes)) {
    return fail(4, "CANONICAL_MISMATCH", "payload bytes are not the canonical encoding of the payload");
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

  const now = options.now ?? new Date();
  const expired = typeof payload.expiresAt === "string" && new Date(payload.expiresAt) < now;
  const result = { ok: true, payload, expired, decision: payload.status, decider: payload.deciderDisplay ?? payload.deciderId ?? null };
  if (payload.canonicalization !== "jcs_v3") {
    if (options.opening) {
      return fail(64, "OPENING_NOT_APPLICABLE", `a request opening applies to jcs_v3 receipts; this one is ${payload.canonicalization} and signs its request in the bytes`);
    }
    return result;
  }

  // jcs_v3, section 6.7. Signed and intact; now the projection must be one
  // the build rule could have produced for its tag (a policy failure if not:
  // the signature is valid, the issuer published a field it must not have).
  const checked = checkPublicProjection(payload.publicProjectionJson);
  if (!checked.ok) return fail(checked.code === "PROJECTION_UNSUPPORTED" ? 8 : 9, checked.code, checked.message);
  if (options.opening) {
    const problem = openRequestCommitment(payload, options.opening.requestJson, options.opening.salt);
    if (problem) return fail(10, problem.code, problem.message);
  }
  return { ...result, projection: checked.projection, projectionTag: checked.tag, commitmentOpened: Boolean(options.opening) };
}

/**
 * Open a jcs_v3 receipt's request commitment (SPEC.md section 6.7, step 2):
 * the supplied request text and salt must reproduce the signed
 * requestCommitment, and the projection rebuilt from that request under the
 * signed tag must equal the signed publicProjectionJson byte for byte. Null
 * when both hold, else { code, message }. Mirrors the issuer's
 * checkReceiptV3RequestBinding (app repo, signing/receipt-v3.ts).
 */
export function openRequestCommitment(payload, requestJson, salt) {
  if (typeof payload?.requestCommitment !== "string" || payload.requestCommitment.length === 0) {
    return { code: "REQUEST_COMMITMENT_UNAVAILABLE", message: "this receipt signs no request commitment" };
  }
  if (typeof requestJson !== "string" || salt == null || salt.length === 0) {
    return { code: "REQUEST_COMMITMENT_UNAVAILABLE", message: "an opening needs the exact request text and its salt" };
  }
  if (salt.length !== 32 || requestCommitment(salt, requestJson) !== payload.requestCommitment) {
    return { code: "REQUEST_COMMITMENT_MISMATCH", message: "the supplied request and salt do not open the signed requestCommitment" };
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

/** Section 9.2 consistency rules; null when the claims agree. */
export function attestationClaimProblem(attestation) {
  if (!OUTCOMES.has(attestation.outcome)) return `unknown outcome ${attestation.outcome}`;
  if (attestation.outputHash !== undefined && !OUTPUT_HASH.test(attestation.outputHash)) return "outputHash is not sha256:<64 hex>";
  if (attestation.outcome === "unknown") {
    if (attestation.finishedAt !== undefined) return "an unknown outcome has no finish time";
    if (attestation.outputHash !== undefined) return "an unknown outcome has no output";
    return null;
  }
  if (attestation.startedAt === undefined || attestation.finishedAt === undefined) {
    return `a ${attestation.outcome} outcome has a start and a finish time`;
  }
  if (new Date(attestation.finishedAt) < new Date(attestation.startedAt)) return "finishedAt is before startedAt";
  return null;
}

function fail(exitCode, code, message) {
  return { ok: false, exitCode, code, message };
}

function usage(message) {
  if (message) console.error(message);
  console.error("usage: node tools/verify.mjs <artifact.json> <keys.json> [--request <request.json> --salt <64 hex>]");
  console.error("       node tools/verify.mjs <attestation.json> <keys.json> --receipt <receipt-artifact.json>");
  process.exit(64);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const flags = {};
  const positional = [];
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index].match(/^--(receipt|request|salt)$/);
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
  const opening = flags.request === undefined ? undefined : { requestJson: readFileSync(flags.request, "utf8"), salt: Buffer.from(flags.salt, "hex") };
  const envelope = JSON.parse(readFileSync(artifactPath, "utf8"));
  const keySet = JSON.parse(readFileSync(keysPath, "utf8"));
  if (envelope.attestation_artifact && !envelope.artifact) {
    if (opening) usage("--request and --salt open a jcs_v3 receipt's commitment, not an attestation");
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
      result.commitmentOpened
        ? `commitment: ${result.payload.requestCommitment} opened with the supplied request and salt; the projection rebuilds from it byte for byte`
        : `commitment: ${result.payload.requestCommitment} (not opened; the request holder opens it with --request <file> --salt <hex>)`
    );
  }
}
