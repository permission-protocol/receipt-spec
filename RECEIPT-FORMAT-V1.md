# Permission Protocol Receipt Format v1 (`pp-receipt-v1`)

## 1. Status

This document specifies version 1 of the Permission Protocol Receipt Format, hereafter `pp-receipt-v1`. It is a stable, published format intended for independent implementation. A receipt conforming to this document is a signed JSON artifact that binds a human authorization decision to concrete operation context and policy metadata.

This is not an IETF standards-track RFC. It is a vendor-published open specification distributed under Apache License 2.0. The intent is interoperability and third-party verification, not closed-platform serialization.

Implementations claiming conformance to `pp-receipt-v1` MUST implement the canonicalization, signature, and verification requirements in this document. Optional behavior is explicitly marked with RFC 2119 keywords.

Versioning in this specification has two axes:

- `receiptVersion` describes the data format version (this document defines `receiptVersion = "v1"`).
- `canonicalization` describes deterministic signature-input construction (this document defines `canonicalization = "jcs_v1"`).

Breaking data-model changes MUST result in a new receipt format major version (for example, `pp-receipt-v2`). Canonicalization changes that alter signed bytes MUST result in a new canonicalization identifier (for example, `jcs_v2`) and MUST NOT be silently introduced into `jcs_v1` implementations.

Permission Protocol maintains this specification, but independent verifiers, issuers, and auditors are expected and encouraged.

## 2. Terminology

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY in this document are to be interpreted as described in RFC 2119.

- Receipt: A signed, structured statement asserting that a named authorization event occurred for a specific request context.
- Signer: The identified principal in the receipt request context (for example, a human reviewer email or ID).
- Issuer: The system that generated and signed the receipt.
- Verifier: Any implementation that validates signature authenticity, receipt shape, and lifecycle constraints.
- Canonicalization: Deterministic construction of the exact byte sequence over which the signature is computed.
- Action: The operation class represented in the receipt request context (for example, `deploy:production`, `tool:write_file`, `payment:refund`).
- Scope: Context fields that bind authorization to a concrete target (for example, repository, commit, environment).
- Signature Key ID: Stable identifier for the public/private keypair used to produce a receipt signature.
- Signed fields: The exact set of fields included in canonicalization and therefore cryptographically protected by the signature.
- Unsigned fields: Fields present in receipt JSON but excluded from canonicalization; they MUST NOT be trusted as cryptographically protected content.

## 3. Data Model

A `pp-receipt-v1` receipt is a JSON object with required signed fields plus required signature material.

### 3.1 Signed field set

The authoritative signed field list for `jcs_v1` is:

1. `id`
2. `companyId`
3. `idemKey`
4. `agentId`
5. `runId`
6. `requestJson`
7. `inputHash`
8. `status`
9. `riskTier`
10. `policyVersion`
11. `reasonCodes`
12. `summary`
13. `receiptVersion`
14. `canonicalization`
15. `signatureAlg`
16. `signatureKeyId`
17. `expiresAt`
18. `createdAt`

Verifiers MUST reject receipts that omit any required v1 signed field. Issuers MUST include all signed fields listed above.

### 3.2 Field definitions

#### `id`
- Type: string
- Required: yes
- Constraints: SHOULD be globally unique per receipt
- Example: `"rcpt_valid_001"`

#### `companyId`
- Type: string
- Required: yes
- Constraints: issuer-defined tenant/account identifier
- Example: `"co_permission_protocol"`

#### `idemKey`
- Type: string
- Required: yes
- Constraints: deduplication or replay-protection correlation key
- Example: `"idem_deploy_abc123"`

#### `agentId`
- Type: string
- Required: yes
- Constraints: issuer-defined agent/runtime identity
- Example: `"agent_prod_1"`

#### `runId`
- Type: string
- Required: yes for v1 verifier conformance
- Constraints: issuer-defined execution/run identifier
- Example: `"run_12345"`

#### `requestJson`
- Type: JSON object
- Required: yes
- Constraints: operation context; nested keys are recursively canonicalized
- Typical fields: `signer`, `action`, `repo`, `commitSha`, plus domain-specific scope fields
- Example:
```json
{
  "signer": "alice@corp.com",
  "action": "deploy:production",
  "repo": "acme/billing-api",
  "commitSha": "9f2c1a7"
}
```

#### `inputHash`
- Type: string
- Required: yes
- Constraints: issuer-defined digest of request input; verifiers treat as opaque signed content
- Example: `"ae1608896372720b6ebb58261e0c0092c608324b0804bc99267c1753990faaa8"`

#### `status`
- Type: string
- Required: yes
- Constraints: lifecycle state; v1 verifiers reject `revoked` regardless of valid signature
- Recommended values: `valid`, `revoked`
- Example: `"valid"`

#### `riskTier`
- Type: string
- Required: yes
- Constraints: issuer policy taxonomy
- Example: `"high"`

#### `policyVersion`
- Type: string
- Required: yes
- Constraints: issuer policy identifier for the decision
- Example: `"prod-deploy-v2"`

#### `reasonCodes`
- Type: JSON array
- Required: yes
- Constraints: issuer-defined reason code list; array order is preserved by canonicalization
- Example: `["POLICY_MATCH"]`

#### `summary`
- Type: string
- Required: yes
- Constraints: human-readable summary of decision context
- Example: `"Approved deploy to production"`

#### `receiptVersion`
- Type: string
- Required: yes
- Constraints: MUST equal `"v1"` for this spec
- Example: `"v1"`

#### `canonicalization`
- Type: string
- Required: yes
- Constraints: MUST equal `"jcs_v1"` for this spec
- Example: `"jcs_v1"`

#### `signatureAlg`
- Type: string
- Required: yes
- Constraints: MUST equal `"ed25519"` for this spec
- Example: `"ed25519"`

#### `signatureKeyId`
- Type: string
- Required: yes
- Constraints: stable key identifier used for public-key resolution
- Example: `"pp-test-2026-q2"`

#### `expiresAt`
- Type: string (ISO 8601 UTC timestamp)
- Required: yes
- Constraints: MUST parse as valid timestamp; verifier MUST reject when current time is at or beyond this value
- Example: `"2026-12-31T00:00:00.000Z"`

#### `createdAt`
- Type: string (ISO 8601 UTC timestamp)
- Required: yes
- Constraints: MUST parse as timestamp-compatible string for ecosystem consistency
- Example: `"2026-04-30T16:23:11.000Z"`

### 3.3 Signature material

#### `signatureValue`
- Type: string (Base64)
- Required: yes
- Signed: no (it is computed from signed fields)
- Constraints: MUST decode to 64-byte Ed25519 signature
- Example: `"jqpqVto2tzudN/g2zNlF0XuiVlRaQr1ESHjKbSjy..."`

### 3.4 Known unsigned fields

The canonical signed field set excludes fields such as `signatureValue`, `updatedAt`, `redeemedAt`, `redeemedRunId`, and `redeemedBy`. Implementations MAY include additional unsigned fields, but verifiers MUST treat them as unauthenticated metadata.

## 4. Canonicalization (`jcs_v1`)

`jcs_v1` defines deterministic serialization of signed fields before signature generation and verification.

### 4.1 Procedure

To canonicalize a receipt:

1. Start with an empty object.
2. For each signed field in the exact list order in Section 3.1:
   - Read the value from the input receipt object.
   - If the value is `undefined` or `null`, omit it from canonical object construction.
   - Otherwise include it.
3. Recursively sort object keys lexicographically by JavaScript string comparison semantics.
4. For arrays, preserve order and recursively canonicalize element values.
5. For Date objects in runtime representations, serialize using `Date.prototype.toISOString()`.
6. Serialize the resulting object with JSON.stringify without extra whitespace.
7. UTF-8 encode that JSON string. The resulting bytes are the signature input.

In deployed verifier behavior for v1 fixtures, required-field validation ensures all signed fields are present before canonicalization.

### 4.2 Determinism requirements

- Implementations MUST produce identical canonical JSON strings for bytewise-identical receipt content.
- Implementations MUST NOT reorder arrays.
- Implementations MUST sort nested object keys recursively.
- Implementations MUST encode canonical JSON using UTF-8.
- Implementations MUST treat canonical bytes as the sole signature truth input.

### 4.3 Exclusions

`signatureValue` MUST NOT be included in canonical bytes. Any field not in Section 3.1 MUST NOT influence signature verification.

### 4.4 Worked example

Given this receipt fragment (plus all required signed fields):

```json
{
  "id": "rcpt_valid_001",
  "requestJson": {
    "repo": "acme/billing-api",
    "action": "deploy:production",
    "signer": "alice@corp.com",
    "commitSha": "9f2c1a7"
  },
  "signatureAlg": "ed25519",
  "canonicalization": "jcs_v1"
}
```

Canonical JSON ordering in `requestJson` becomes `action`, `commitSha`, `repo`, `signer`, and top-level keys are sorted in canonical output. A full fixture canonical output therefore has stable ordering regardless of source document field order.

Implementers can inspect fixture-derived canonical JSON by applying the reference algorithm and then converting to bytes.

Example byte production (conceptual):

```text
canonical-json-string --UTF-8--> canonical-bytes --SHA-256--> canonical-digest
```

The `conformance/expected-canonical-bytes.txt` file publishes SHA-256 digests of canonical bytes for the five normative fixtures.

## 5. Signing

### 5.1 Algorithm

`pp-receipt-v1` signatures use Ed25519 as defined in RFC 8032.

- `signatureAlg` MUST be `ed25519`.
- The signed message MUST be exactly the canonical UTF-8 byte array from Section 4.
- The signature MUST be encoded as Base64 text in `signatureValue`.

### 5.2 Signature encoding

The signature is raw 64-byte Ed25519 output. It is represented as RFC 4648 Base64 text for JSON transport. Receivers MUST decode `signatureValue` from Base64 before verification.

### 5.3 Key binding

Each signed receipt includes `signatureKeyId`. Verifiers MUST resolve a public key corresponding to that value before cryptographic verification.

If a verifier is configured with an explicit expected key ID, it SHOULD reject receipts whose `signatureKeyId` does not match expected policy.

### 5.4 Issuance requirements

Issuers claiming conformance MUST:

- Include all signed fields listed in Section 3.1.
- Set `canonicalization = "jcs_v1"` and `signatureAlg = "ed25519"`.
- Compute canonical bytes exactly as specified.
- Sign canonical bytes with the private key corresponding to `signatureKeyId`.
- Publish matching public key material for verifier discovery.

## 6. Verification

A conformant verifier MUST execute the following 11-step procedure, derived from the reference verifier behavior.

1. Parse receipt as a JSON object. If parsing fails or root is not an object, fail as malformed.
2. Assert presence of every required signed field in Section 3.1. If any is missing, fail as malformed.
3. Assert `canonicalization` equals `jcs_v1`. Otherwise fail as malformed/unsupported canonicalization.
4. Assert `signatureAlg` equals `ed25519`. Otherwise fail as malformed/unsupported algorithm.
5. Assert `signatureValue` exists and is a string. Otherwise fail as malformed.
6. Resolve public key for `signatureKeyId` via configured key source (local file and/or network endpoint). If resolution fails, fail as key-resolution error.
7. Canonicalize receipt using Section 4 and produce canonical UTF-8 bytes.
8. Decode `signatureValue` from Base64 and verify Ed25519 signature against canonical bytes and resolved key. If verification fails, fail as signature invalid.
9. Parse `expiresAt` as timestamp. If invalid timestamp syntax, fail as malformed.
10. Compare verifier current time to `expiresAt`. If receipt is expired (current time >= `expiresAt`), fail as expired/revoked.
11. Check `status`. If `status == "revoked"`, fail as expired/revoked. Otherwise succeed.

### 6.1 Verification outputs

Conformant verifier implementations SHOULD provide both machine-readable and human-readable output. Exit code classes used by the reference verifier are:

- `0`: valid
- `1`: signature invalid
- `2`: expired or revoked
- `3`: malformed receipt
- `4`: key resolution failed
- `64`: CLI usage error (tooling layer)

### 6.2 Trust boundary

Successful verification proves only that:

- The signed fields were produced by someone controlling the private key for `signatureKeyId`.
- The receipt was not tampered within signed fields.
- The receipt is not expired and not explicitly revoked according to encoded status.

Verification does not prove that the original human decision was correct, lawful, or high quality.

## 7. Key Discovery

Public keys are discoverable by key ID. Typical endpoints:

- `https://<issuer>/api/v1/keys/<keyId>`
- `https://<issuer>/api/v1/keys/current`

### 7.1 Key representation

A key response SHOULD include at least:

```json
{
  "keyId": "pp-test-2026-q2",
  "algorithm": "ed25519",
  "publicKey": "MCowBQYDK2VwAyEAutC/MffkkEO2hXR37Ilq4ut4UpZwdrwmtbGw/eEymo0=",
  "status": "active",
  "createdAt": "2026-04-30T00:00:00.000Z"
}
```

`publicKey` may be encoded as Base64 DER SubjectPublicKeyInfo or represented as PEM in alternate transport channels. Verifiers MUST decode key material into an Ed25519 public key object compatible with their crypto runtime.

### 7.2 Caching guidance

Verifiers SHOULD cache discovered public keys for at least 24 hours to reduce network dependence and improve reliability. Verifiers MUST support key rotation by selecting key material via `signatureKeyId` rather than assuming a single global active key forever.

### 7.3 Offline verification

Verifiers MAY run fully offline when key material is supplied via local file or preloaded trust store. In offline mode, missing key material MUST be treated as verification failure rather than silent success.

## 8. Lifecycle

### 8.1 Status semantics

Receipt `status` carries issuer lifecycle state.

Recommended semantics for v1:

- `valid`: cryptographically valid and not revoked by status field.
- `revoked`: signature remains mathematically valid for historic bytes, but verifier MUST treat receipt as invalid for authorization acceptance.

Some ecosystems may also expose informational lifecycle values (for example, `signed` or `expired`) in external indexes. Those values are not part of v1 verifier acceptance logic unless encoded in signed fields and mapped by policy.

### 8.2 Expiration

`expiresAt` is mandatory in v1 and is part of signed content. This prevents post-issuance extension without re-signing.

Conformant verifiers MUST reject receipts where current verifier time is greater than or equal to `expiresAt`.

### 8.3 Revocation model

In v1, revocation is advisory from a cryptography perspective: signing proof still shows a key signed the bytes. However, policy acceptance MUST consider revocation state. A strict verifier for authorization use MUST reject revoked receipts even if signatures are valid.

### 8.4 Redemption and replay controls

Replay mitigation is an application concern layered on top of signature validity. `idemKey` SHOULD be used by integrators to implement single-use or deduplicated execution gates. A verifier MAY maintain an external redemption store keyed by `idemKey` and reject second use attempts.

## 9. Security Considerations

### 9.1 Replay attacks

Signatures alone do not prevent replay of a previously valid receipt. Systems using receipts for one-time execution MUST enforce replay controls, typically using `idemKey`, `runId`, and scoped context checks. Reuse detection SHOULD be atomic in distributed systems.

### 9.2 Time skew

Verification depends on verifier clock correctness. Systems SHOULD use trusted time synchronization. Implementations MAY apply a small skew tolerance window (for example, 5 minutes) based on risk appetite; such tolerance should be explicit and auditable.

### 9.3 Key compromise and rotation

Compromise of signing private keys permits forged receipts. Issuers MUST support key rotation and revocation procedures. Verifiers MUST bind trust decisions to `signatureKeyId` and SHOULD monitor key-status changes from issuer key metadata.

### 9.4 Canonicalization fragility

Any canonicalization mismatch causes signature failure. Implementers MUST test against published fixtures and canonical-byte digests. Changes in JSON serialization libraries, Unicode handling, or object-key traversal MAY break interoperability if not validated.

### 9.5 Unsigned metadata misuse

Fields outside signed set are mutable and untrusted. Consumers MUST NOT make authorization decisions from unsigned fields unless independently validated.

### 9.6 Scope validation gaps

A valid signature does not prove the receipt matches the operation currently being attempted unless verifier/application compares expected scope fields (such as action, repo, commit, environment) against `requestJson` and related signed content.

### 9.7 Algorithm agility

v1 intentionally fixes `signatureAlg` to Ed25519 for operational simplicity. Future algorithms require explicit versioning and migration pathways; algorithm downgrades MUST NOT be accepted silently.

## 10. Versioning Policy

### 10.1 Receipt version

`receiptVersion` for this specification is `"v1"`.

Breaking changes to field semantics, required fields, signature rules, or verifier acceptance criteria MUST use a new receipt version namespace (for example, `v2`).

### 10.2 Canonicalization version

`canonicalization` for this specification is `"jcs_v1"`.

A change that alters canonical bytes for any existing receipt content is breaking for signatures and MUST use a new canonicalization identifier (for example, `jcs_v2`). Verifiers MUST reject unsupported canonicalization identifiers unless they explicitly implement them.

### 10.3 Forward compatibility

Future optional fields MAY be added to receipts, but they do not become cryptographically relevant unless included in a future signed-field set. Implementers SHOULD ignore unknown fields unless policy says otherwise.

### 10.4 Compatibility claims

An implementation claiming `pp-receipt-v1` compatibility MUST:

- Verify required fields and required constants.
- Implement `jcs_v1` canonicalization exactly.
- Verify Ed25519 signatures over canonical bytes.
- Enforce expiration and revoked status checks.
- Pass fixture conformance described in Section 11.

## 11. Conformance

### 11.1 Normative fixture set

This specification publishes five normative fixtures under `fixtures/`:

- `valid-deploy.json`
- `valid-mcp.json`
- `valid-payment.json`
- `expired.json`
- `tampered.json`

### 11.2 Required verifier outcomes

Conformant verifiers MUST produce these outcomes with supplied test key material:

- `valid-deploy.json` -> valid
- `valid-mcp.json` -> valid
- `valid-payment.json` -> valid
- `expired.json` -> expired/revoked class failure
- `tampered.json` -> signature invalid failure

### 11.3 Canonical-byte digest matching

Implementations MUST produce canonical UTF-8 bytes for each fixture and SHOULD compute SHA-256 digest of those bytes. Digests MUST match published values in `conformance/expected-canonical-bytes.txt`.

Digest mismatch indicates canonicalization divergence and therefore non-conformance.

### 11.4 Reference verifier linkage

The TypeScript CLI at `https://github.com/permission-protocol/pp-cli` is a reference verifier implementation for `pp-receipt-v1`. Independent implementations in other languages are encouraged and SHOULD use this spec and fixture suite as their interoperability baseline.

### 11.5 Conformance script

`conformance/verify.sh` provides a minimal execution check against expected verifier exit codes. It is intended as a sanity gate, not a complete certification program.

## Appendix B: Implementation Notes (Informative)

This appendix is not normative, but captures practical guidance observed while building interoperable tooling.

### B.1 Field-type tolerance versus strictness

The reference verifier enforces presence of required signed fields and required constant values, then performs cryptographic validation. It does not currently enforce deep schema typing for every nested member in `requestJson`. Third-party verifiers MAY enforce stricter schemas for local policy, but SHOULD separate schema-policy failures from cryptographic failures in output classification. Doing so improves debugging and keeps interoperability behavior predictable.

### B.2 `requestJson` and scope modeling

`requestJson` is intentionally flexible to support multiple domains (deploy, MCP tooling, payment controls, and future authority surfaces). Flexibility does not remove the need for verifier-side policy checks. Integrators SHOULD define explicit expected keys and semantic checks per action class. For example, a deploy verifier might require `repo` and `commitSha`, while a payment verifier might require amount, currency, and payment identifier fields.

### B.3 Canonicalization drift testing

A common implementation risk is accidental canonicalization drift introduced by language runtime upgrades or helper library changes. Teams SHOULD add fixture digest comparison to CI, and SHOULD treat digest changes as potentially breaking security events rather than routine refactors. Any drift that changes signed bytes can invalidate existing signatures.

### B.4 Operational logging

Verifiers SHOULD log at least receipt ID, key ID, verification outcome class, and timestamp. Logs SHOULD avoid sensitive request payload leakage unless required for forensic policy and compliant with local retention requirements. When possible, include canonical-byte digest in debug logs to accelerate cross-implementation troubleshooting.

### B.5 Migration planning

When preparing for future versions (`receiptVersion` or `canonicalization` updates), implementations SHOULD support dual-stack verification during migration windows. A pragmatic strategy is:

1. Add explicit parser/version routing.
2. Add fixture suites per version.
3. Roll out verifier support before issuer cutover.
4. Monitor failure codes by version and key ID.

This sequence minimizes production breakage while preserving cryptographic correctness guarantees.

## Appendix A: Full Example Receipt (Informative)

```json
{
  "id": "rcpt_valid_001",
  "companyId": "co_permission_protocol",
  "idemKey": "idem_abc123",
  "agentId": "agent_prod_1",
  "runId": "run_12345",
  "requestJson": {
    "signer": "alice@corp.com",
    "action": "deploy:production",
    "repo": "acme/billing-api",
    "commitSha": "9f2c1a7"
  },
  "inputHash": "ae1608896372720b6ebb58261e0c0092c608324b0804bc99267c1753990faaa8",
  "status": "valid",
  "riskTier": "high",
  "policyVersion": "prod-deploy-v2",
  "reasonCodes": [
    "POLICY_MATCH"
  ],
  "summary": "Approved deploy to production",
  "receiptVersion": "v1",
  "canonicalization": "jcs_v1",
  "signatureAlg": "ed25519",
  "signatureKeyId": "pp-test-2026-q2",
  "expiresAt": "2026-12-31T00:00:00.000Z",
  "createdAt": "2026-04-30T16:23:11.000Z",
  "signatureValue": "jqpqVto2tzudN/g2zNlF0XuiVlRaQr1ESHjKbSjyahvO9gbNvZdfTKRTK80iOiDv1ZFjFG9/NCQKqrkvQRKqDQ==",
  "redeemedAt": "2026-04-30T17:00:00.000Z"
}
```
