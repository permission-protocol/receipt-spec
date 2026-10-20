// Reference implementation of the jcs_v1, jcs_v2 and jcs_v3 canonicalization
// described in SPEC.md section 4. Dependency-free. Byte-for-byte equivalent to
// the hosted service's canonicalizeReceiptForVersion (app repo,
// src/lib/permission-protocol-v1/signing/canonicalize.ts); SPEC.md section 12
// records the byte-for-byte check against the issuer's signer.
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

// jcs_v3 (SPEC.md section 3.4): written out in full, not derived from v2, so
// the frozen contents are visible. Removed from v2: companyId, idemKey,
// requestJson, inputHash and summary (the summary is committed inside the
// request under receiptSummary instead, section 3.5). Added: requestCommitment
// (section 3.5), publicProjectionJson (section 3.6) and deciderProof (section
// 3.8, an object, absent when the decider did not step up). Order is
// irrelevant to the bytes (keys are sorted); it matches the issuer's list.
export const SIGNED_FIELDS_V3 = [
  "id",
  "agentId",
  "runId",
  "requestCommitment",
  "publicProjectionJson",
  "status",
  "riskTier",
  "policyVersion",
  "reasonCodes",
  "receiptVersion",
  "canonicalization",
  "signatureAlg",
  "signatureKeyId",
  "expiresAt",
  "createdAt",
  "deciderId",
  "deciderDisplay",
  "deciderAuthMethod",
  "deciderProof",
  "resolutionType",
  "attributionConfidence",
  "scope",
];

/**
 * A canonicalization value this implementation does not define. Typed so a
 * verifier reports it as unverifiable here (CANONICALIZATION_UNSUPPORTED),
 * never as tampered, and never re-canonicalizes the bytes under another
 * version's field list.
 */
export class CanonicalizationUnsupportedError extends Error {
  constructor(canonicalization) {
    super(`unsupported canonicalization: ${canonicalization}`);
    this.name = "CanonicalizationUnsupportedError";
    this.code = "CANONICALIZATION_UNSUPPORTED";
    this.canonicalization = canonicalization;
  }
}

export function signedFieldsFor(canonicalization) {
  if (canonicalization === "jcs_v3") return SIGNED_FIELDS_V3;
  if (canonicalization === "jcs_v2") return SIGNED_FIELDS_V2;
  if (canonicalization === "jcs_v1") return SIGNED_FIELDS_V1;
  throw new CanonicalizationUnsupportedError(canonicalization);
}

function sortKeys(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const sorted = {};
  // defineProperty, not assignment: a JSON key named "__proto__" stays an own
  // key of the copy (assignment would set the prototype and drop the key).
  for (const key of Object.keys(value).sort()) {
    Object.defineProperty(sorted, key, { value: sortKeys(value[key]), enumerable: true, writable: true, configurable: true });
  }
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

/** jcs_v3 request commitment salts are exactly this many bytes. */
export const REQUEST_COMMITMENT_SALT_BYTES = 32;

/**
 * jcs_v3 requestCommitment (SPEC.md section 3.5):
 * "sha256:" + lowercase hex SHA-256( salt || UTF-8(requestJson) ), over the
 * exact request text, never a re-serialization of it.
 */
export function requestCommitment(salt, requestJson) {
  if (salt.length !== REQUEST_COMMITMENT_SALT_BYTES) {
    throw new RangeError(`a request commitment salt is exactly ${REQUEST_COMMITMENT_SALT_BYTES} bytes (got ${salt.length})`);
  }
  return `sha256:${createHash("sha256").update(salt).update(Buffer.from(requestJson, "utf8")).digest("hex")}`;
}

/**
 * The reserved top-level request key that carries a jcs_v3 receipt's summary
 * (SPEC.md section 3.5). Only the issuer's mint sets it, and no projection
 * allowlist names it.
 */
export const RECEIPT_SUMMARY_REQUEST_KEY = "receiptSummary";

/**
 * The reserved top-level request key that binds a jcs_v3 receipt to its
 * workspace and idempotency record (SPEC.md section 3.5): an object with
 * exactly these three keys, each the issuer's stored value (a string) or null.
 * jcs_v2 signed the three fields; jcs_v3 commits them here instead. Only the
 * issuer's mint sets it, always, and no projection allowlist names it.
 */
export const RECEIPT_BINDING_REQUEST_KEY = "receiptBinding";
export const RECEIPT_BINDING_FIELDS = Object.freeze(["companyId", "idemKey", "inputHash"]);

/** Keys only the mint writes into a committed request. A request handed to the mint that carries one is refused. */
export const RESERVED_REQUEST_KEYS = Object.freeze([RECEIPT_BINDING_REQUEST_KEY, RECEIPT_SUMMARY_REQUEST_KEY]);

/** A refusal of the mint side (SPEC.md section 3.5), typed as the issuer types it. */
export class ReceiptV3MintError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ReceiptV3MintError";
    this.code = code;
  }
}

/** The canonical text of a request: keys sorted recursively, no whitespace. */
export function canonicalRequestJson(requestJson) {
  return JSON.stringify(sortKeys(JSON.parse(requestJson)));
}

/**
 * Null when `value` is a receiptBinding as the mint writes it: a JSON object
 * with exactly the keys companyId, idemKey and inputHash, each a string or
 * null. Otherwise a description of the first defect.
 */
export function receiptBindingProblem(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return `${RECEIPT_BINDING_REQUEST_KEY} is not a JSON object`;
  const keys = Object.keys(value);
  const extra = keys.filter((key) => !RECEIPT_BINDING_FIELDS.includes(key));
  if (extra.length) return `${RECEIPT_BINDING_REQUEST_KEY} carries keys outside companyId, idemKey and inputHash: ${extra.join(", ")}`;
  for (const field of RECEIPT_BINDING_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) return `${RECEIPT_BINDING_REQUEST_KEY}.${field} is missing`;
    if (value[field] !== null && typeof value[field] !== "string") return `${RECEIPT_BINDING_REQUEST_KEY}.${field} is neither a string nor null`;
  }
  return null;
}

/**
 * The binding the mint commits for a stored row: its companyId, idemKey and
 * inputHash, each the stored string or null when the row has none.
 */
export function receiptBindingFor(row) {
  const binding = Object.fromEntries(RECEIPT_BINDING_FIELDS.map((field) => [field, row[field] ?? null]));
  const problem = receiptBindingProblem(binding);
  if (problem) throw new ReceiptV3MintError("RECEIPT_BINDING_INVALID", problem);
  return binding;
}

/**
 * The mint side of the committed request (SPEC.md section 3.5), as the
 * issuer's buildReceiptV3RequestBinding does it: parse the request (JSON text
 * of an object, else REQUEST_NOT_OBJECT); refuse one that already carries a
 * reserved key (REQUEST_RESERVED_KEY); add the binding under receiptBinding,
 * always, and the summary under receiptSummary when it is a string; and
 * serialize canonically. That text is the stored requestJson the commitment
 * covers. The request handed in need not be canonical text: the mint
 * canonicalizes it.
 */
export function committedRequestJson(requestJson, summary, binding) {
  let request;
  try {
    request = typeof requestJson === "string" ? JSON.parse(requestJson) : undefined;
  } catch {
    request = undefined;
  }
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new ReceiptV3MintError("REQUEST_NOT_OBJECT", "the request is not a JSON object");
  }
  for (const key of RESERVED_REQUEST_KEYS) {
    if (Object.prototype.hasOwnProperty.call(request, key)) {
      throw new ReceiptV3MintError("REQUEST_RESERVED_KEY", `the request already carries the reserved key "${key}"; only the mint sets it`);
    }
  }
  const problem = receiptBindingProblem(binding);
  if (problem) throw new ReceiptV3MintError("RECEIPT_BINDING_INVALID", problem);
  const committed = { ...request, [RECEIPT_BINDING_REQUEST_KEY]: { ...binding } };
  if (typeof summary === "string") committed[RECEIPT_SUMMARY_REQUEST_KEY] = summary;
  return JSON.stringify(sortKeys(committed));
}

// ---------------------------------------------------------------------------
// Execution attestations (SPEC.md section 9). `attest_v1` is the attestation's
// own canonicalization id, not a receipt version. Same byte rules as above,
// its own frozen field list. Byte-for-byte equivalent to the hosted service's
// canonicalizeAttestation (app repo,
// src/lib/permission-router/execution-attestation.ts).
// ---------------------------------------------------------------------------

export const ATTESTATION_SIGNED_FIELDS_V1 = [
  "approvalReceiptId",
  "outcome",
  "toolCallId",
  "outputHash",
  "startedAt",
  "finishedAt",
  "attestationVersion",
  "canonicalization",
  "signatureAlg",
  "signatureKeyId",
  "createdAt",
];

/** Canonical JSON text of an attestation's signed field set (attest_v1). */
export function canonicalizeAttestation(attestation) {
  if (attestation.canonicalization !== "attest_v1") {
    throw new Error(`unsupported attestation canonicalization: ${attestation.canonicalization}`);
  }
  const canonical = {};
  for (const field of ATTESTATION_SIGNED_FIELDS_V1) {
    const value = attestation[field];
    if (value !== undefined && value !== null) canonical[field] = serializeValue(value);
  }
  return JSON.stringify(sortKeys(canonical));
}

export function attestationBytes(attestation) {
  return Buffer.from(canonicalizeAttestation(attestation), "utf8");
}

/** outputHash: "sha256:" + hex SHA-256 of the canonical JSON of the adapter output. */
export function outputHash(output) {
  return `sha256:${createHash("sha256").update(JSON.stringify(sortKeys(output)), "utf8").digest("hex")}`;
}
