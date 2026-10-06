// Reference verifier for a receipt artifact (SPEC.md section 6) and an
// execution attestation (SPEC.md section 9). Dependency-free.
//
//   node tools/verify.mjs <artifact.json> <keys.json>
//   node tools/verify.mjs <attestation.json> <keys.json> --receipt <receipt-artifact.json>
//
// Both inputs are local files, so this runs with no network and no Permission
// Protocol service in the loop. Exit codes: 0 verified, 1 signature invalid,
// 2 key not found or revoked, 3 malformed, 4 payload does not match its hash
// or its own canonicalization.
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { attestationBytes, canonicalBytes, signingDigest } from "./canonicalize.mjs";

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
  return { ok: true, payload, expired, decision: payload.status, decider: payload.deciderDisplay ?? payload.deciderId ?? null };
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

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const receiptFlag = args.indexOf("--receipt");
  const receiptPath = receiptFlag === -1 ? null : args[receiptFlag + 1];
  const [artifactPath, keysPath] = receiptFlag === -1 ? args : args.filter((_, index) => index !== receiptFlag && index !== receiptFlag + 1);
  if (!artifactPath || !keysPath) {
    console.error("usage: node tools/verify.mjs <artifact.json> <keys.json> [--receipt <receipt-artifact.json>]");
    process.exit(64);
  }
  const envelope = JSON.parse(readFileSync(artifactPath, "utf8"));
  const keySet = JSON.parse(readFileSync(keysPath, "utf8"));
  if (envelope.attestation_artifact && !envelope.artifact) {
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
  const result = verifyArtifact(envelope, keySet);
  if (!result.ok) {
    console.error(`FAILED ${result.code}: ${result.message}`);
    process.exit(result.exitCode);
  }
  console.log(`VERIFIED ${result.payload.id}`);
  console.log(`decision: ${result.decision}${result.expired ? " (expired for redemption; signature still valid)" : ""}`);
  console.log(`decider: ${result.decider} (${result.payload.deciderId})`);
  console.log(`policy: ${result.payload.policyVersion ?? "none"}`);
}
