// Reference verifier for a receipt artifact (SPEC.md section 6). Dependency-free.
//
//   node tools/verify.mjs <artifact.json> <keys.json>
//
// Both inputs are local files, so this runs with no network and no Permission
// Protocol service in the loop. Exit codes: 0 verified, 1 signature invalid,
// 2 key not found or revoked, 3 malformed, 4 payload does not match its hash
// or its own canonicalization.
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { canonicalBytes, signingDigest } from "./canonicalize.mjs";

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

function fail(exitCode, code, message) {
  return { ok: false, exitCode, code, message };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [artifactPath, keysPath] = process.argv.slice(2);
  if (!artifactPath || !keysPath) {
    console.error("usage: node tools/verify.mjs <artifact.json> <keys.json>");
    process.exit(64);
  }
  const envelope = JSON.parse(readFileSync(artifactPath, "utf8"));
  const keySet = JSON.parse(readFileSync(keysPath, "utf8"));
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
