// Reference implementation of the jcs_v1 and jcs_v2 canonicalization described in
// SPEC.md section 4. Dependency-free. Byte-for-byte equivalent to the hosted
// service's canonicalizeReceiptForVersion (app repo,
// src/lib/permission-protocol-v1/signing/canonicalize.ts); tools/generate-vectors.mjs
// cross-checks that equivalence when the app checkout is available.
import { createHash } from "node:crypto";

export const SIGNED_FIELDS_V1 = [
  "id",
  "companyId",
  "idemKey",
  "agentId",
  "runId",
  "requestJson",
  "inputHash",
  "status",
  "riskTier",
  "policyVersion",
  "reasonCodes",
  "summary",
  "receiptVersion",
  "canonicalization",
  "signatureAlg",
  "signatureKeyId",
  "expiresAt",
  "createdAt",
];

export const SIGNED_FIELDS_V2 = [
  ...SIGNED_FIELDS_V1,
  "deciderId",
  "deciderDisplay",
  "deciderAuthMethod",
  "resolutionType",
  "attributionConfidence",
  "scope",
];

export function signedFieldsFor(canonicalization) {
  if (canonicalization === "jcs_v2") return SIGNED_FIELDS_V2;
  if (canonicalization === "jcs_v1") return SIGNED_FIELDS_V1;
  throw new Error(`unsupported canonicalization: ${canonicalization}`);
}

function sortKeys(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const sorted = {};
  for (const key of Object.keys(value).sort()) sorted[key] = sortKeys(value[key]);
  return sorted;
}

function serializeValue(value) {
  return value instanceof Date ? value.toISOString() : value;
}

/** Canonical JSON text of the signed field set for the receipt's canonicalization. */
export function canonicalize(receipt, canonicalization = receipt.canonicalization) {
  const fields = signedFieldsFor(canonicalization);
  const canonical = {};
  for (const field of fields) {
    const value = receipt[field];
    if (value !== undefined && value !== null) canonical[field] = serializeValue(value);
  }
  return JSON.stringify(sortKeys(canonical));
}

/** The exact bytes the issuer hashes: UTF-8 of the canonical JSON text. */
export function canonicalBytes(receipt, canonicalization) {
  return Buffer.from(canonicalize(receipt, canonicalization), "utf8");
}

/** The 32-byte Ed25519 message: SHA-256 over the canonical bytes. */
export function signingDigest(bytes) {
  return createHash("sha256").update(bytes).digest();
}
