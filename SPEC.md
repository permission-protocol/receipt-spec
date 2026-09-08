# Permission Protocol Receipt Format, as emitted

**Version markers covered:** `receiptVersion` `2`, `canonicalization` `jcs_v2`. **Status:** describes what the hosted service at `app.permissionprotocol.com` has issued since 2026-07-09, traced field by field to the code that writes it. **Date:** 2026-09-08. **License:** CC BY 4.0 for this text; Apache-2.0 for the schemas, vectors, and tools.

This document supersedes `RECEIPT-FORMAT-V1.md` as the description of the current format. The v1 document stays in this repository unchanged, because it is what `jcs_v1` receipts were published against; section 5.5 records where it disagreed with the product.

## 1. Purpose and scope

A receipt is a signed statement that one decision was made about one gated action: approved or denied, by whom, under which policy version, at what time, against which exact action snapshot. It is issued by the system that made or recorded the decision and verified by anyone holding the issuer's public key. It proves authorization. It does not prove that the action ran, that it succeeded, or that the decision was wise.

In scope: the signed payload (section 3), how its bytes are built (section 4), how they are signed and how keys are found (section 5), the portable envelope and the verify procedure (section 6), and what the decision and decider fields mean (section 7).

Out of scope: the policy language, the approval user interface, and the storage of receipts. Verifiers need none of them.

Key words MUST, MUST NOT, SHOULD, and MAY are as in RFC 2119.

## 2. Terminology

- **Gated action**: an action that passed through a Permission Protocol enforcement point. Only gated actions produce receipts.
- **Decision**: `APPROVED` or `DENIED`. Holds awaiting a human, expiries, and errors are states, not decisions, and are not signed.
- **Decider**: who resolved the decision: a human over an authenticated session, a machine credential, an anonymous demo signer, or the deterministic policy engine.
- **Lane**: a mint path. Two lanes emit production receipts today: the **deploy-gate lane** (pull-request and deploy approvals surfaced as a GitHub required check) and the **execute lane** (agent and tool calls submitted to the permission router at `/api/v1/execute` and `/api/permission/v1/execute`). A third, the ledger lane of the older PPv1 engine, is not routed today.
- **Signed payload**: the JSON object whose canonical bytes the signature covers. Section 3.
- **Artifact**: the portable envelope carrying the signed bytes, the signature, the digest, and the key id. Section 6.1.
- **Issuer**: the party holding the private key for `signatureKeyId`.

## 3. Data model

### 3.1 The signed payload

The signed payload is a flat JSON object. Its field names are the hosted service's stored column names, which is what lets the issuer re-canonicalize a stored row and detect post-signing mutation. A field whose stored value is null is **absent** from the payload; it is never present with a null value (section 4, step 2).

| Field | Type | Present | Meaning and how the lanes fill it |
|---|---|---|---|
| `id` | string | always | Receipt identifier. Deploy gate: `rcpt_dg_<requestId>` (re-approvals append `_reapproval_<epoch ms>`). Execute lane: the row's generated id. |
| `companyId` | string | always | Issuer-side tenant id. Opaque to verifiers. |
| `idemKey` | string | always | Idempotency key, unique per `(companyId, idemKey)`. Execute lane: the caller's `constraints.idempotencyKey`, else the `inputHash`. Deploy gate: `deploy-gate:<requestId>:<scopeHash>`. |
| `agentId` | string | always | The acting agent as the caller named it. Deploy gate always writes `github-actions`. Permission Protocol does not issue agent identity; it records what the customer's registry supplied. |
| `runId` | string | optional | Run or session id supplied by the caller. |
| `requestJson` | string | always | The action snapshot as JSON **text** with recursively sorted keys and no whitespace. A string, not an object. Section 3.3. |
| `inputHash` | string | always | Deploy gate: bare lowercase hex SHA-256 over the request scope (env, repo, ref, commit, capability, workflow, artifact digest). Execute lane: `sha256:<hex>` over the canonical hashable request (`pp.hashable_payload.v1`: tenant, actor, intent, action, context, stable constraints). Two shapes; the schema accepts both. |
| `status` | string | always | `APPROVED` or `DENIED`. Section 7.1. |
| `riskTier` | string | optional | Execute lane only: `A_READONLY`, `B_DRAFT`, `C_EXECUTE_WITH_APPROVAL`, `D_PROHIBITED`. Absent on deploy-gate receipts and on execute-lane denials made before risk classification (kill switch, hash mismatch). |
| `policyVersion` | string | optional | The policy version that governed the decision. Deploy gate: `deploy-gate-v1`. Execute lane: the router's policy version (`pol_v1_hardcoded` today) or `<ruleId>@<ruleVersion>` for a scoped intake rule. Absent on kill-switch denials. |
| `reasonCodes` | string | optional | A JSON array of strings, serialized as text. Order preserved. Examples: `["DEPLOY_GATE_APPROVED"]`, `["READONLY_OPERATION"]`, `["GLOBAL_FREEZE_ACTIVE","KILL_SWITCH_DENIAL_TERMINAL"]`, `["APPROVAL_DENIED","FOUNDER_VETO_REQUESTED"]`. |
| `summary` | string | optional | Human-readable summary of the decision context. |
| `deciderId` | string | always (v2) | Stable id of who decided. Section 7.2 lists every form in use. |
| `deciderDisplay` | string | always (v2) | Human-facing label: the GitHub login for a session signer, a fixed label for the policy engine, a role-class label on the execute lane. |
| `deciderAuthMethod` | string | optional (v2) | `session`, `api_key`, `anonymous_demo`, or `policy`. Absent where the mint path recorded null: the deploy-gate webhook auto-clearance (`system/pp-engine`). |
| `resolutionType` | string | optional (v2) | `allow_once`, `allow_always`, or `deny`. Absent on policy-engine decisions on the execute and ledger lanes: the engine cleared or denied under policy, it did not allow once. |
| `attributionConfidence` | string | always (v2) | `credentialed`, `heuristic`, or `unattributed`. Section 7.3. |
| `scope` | string | always (v2) | `production` or `demo`. A demo receipt is signed under a distinct demo key and can never pass as production evidence. |
| `receiptVersion` | integer | always | `2`. An integer, not a string. |
| `canonicalization` | string | always | `jcs_v2`. |
| `signatureAlg` | string | always | `ed25519`. |
| `signatureKeyId` | string | always | Names the issuer key. Resolve it through the published key set before verifying. |
| `expiresAt` | string | always | ISO 8601 UTC with milliseconds (`Date.prototype.toISOString`). Bounds one-time redemption of an approval (deploy gate: 15 minutes by default; execute lane: one hour). The signature stays valid evidence after expiry. |
| `createdAt` | string | always | ISO 8601 UTC with milliseconds. When the row was created. Decision receipts on both lanes are signed when the decision lands, so for those it is also the decision time. |

`schema/receipt-v2.json` encodes this table. It marks `additionalProperties: false`: a payload carrying any other key was not produced under `jcs_v2`.

### 3.2 Fields the signature does not cover

The issuer stores more than it signs. `signatureValue`, `signedPayloadBytes`, `signedPayloadHash`, `signerOrigin`, `redeemedAt`, `redeemedRunId`, `redeemedBy`, `approvalId`, `linkedApprovalId`, `policySnapshotBefore`, `policySnapshotAfter`, `executionJson`, `errorJson`, `receiptType`, and `updatedAt` are outside the signed set. In particular:

- **Execution outcome is not signed.** `executionJson` records what a tool returned on the execute lane; it is unsigned and may be absent. A receipt proves authorization, not completion. A design to make the outcome a separate signed attestation referencing the approval receipt is under review in `permission-protocol/app` (issue #7).
- **Redemption is issuer state.** One-time redemption (`redeemedAt`) is enforced by the issuer's verify endpoint for CI gates. It is not evidence and it is not signed.

### 3.3 `requestJson`

`requestJson` is the exact action the decider saw, serialized once by the issuer with recursively sorted keys and no whitespace, then stored and signed as a string. Signing the string rather than an embedded object is deliberate: the bytes cannot drift with a re-serialization.

Its contents are lane-specific and issuer-defined. Verifiers MUST treat `requestJson` as authenticated **text** and MAY parse it for display or scope checks. The two shapes today:

- Deploy gate: `{ action: { operation: "deploy", tool: "github-actions" }, context: { environment, reversibility: "REVERSIBLE" }, enrichmentSnapshot, intent: { category: "deployment", name: "deploy_gate_approval", summary }, metadata: { deployGateRequestId, ... demo markers when scope is demo }, policy: { decision, expiresAt }, scope: { artifact_digest, capability, commitSha, env, ref, repo, workflow } }`.
- Execute lane: the caller's full request as canonical JSON: `{ action: { operation, parameters, tool }, actor: { agentId, runId }, constraints?, context: { environment, reversibility, ... }, hashes: { inputHash }, intent: { category, name, summary }, tenantId }`.

A verifier checking that a receipt covers the action in front of it compares the fields it cares about (repository, commit, tool, parameters) against the parsed `requestJson`, and the digest of its own canonical input against `inputHash`.

## 4. Canonicalization (`jcs_v2`)

The signed bytes are built as follows. This is exactly the issuer's procedure; `tools/canonicalize.mjs` is a dependency-free reference implementation that CI checks byte for byte against the vectors and against a live production receipt.

1. Take the frozen signed field list for the receipt's `canonicalization` value. For `jcs_v2` that is the 18 `jcs_v1` fields (`id`, `companyId`, `idemKey`, `agentId`, `runId`, `requestJson`, `inputHash`, `status`, `riskTier`, `policyVersion`, `reasonCodes`, `summary`, `receiptVersion`, `canonicalization`, `signatureAlg`, `signatureKeyId`, `expiresAt`, `createdAt`) plus `deciderId`, `deciderDisplay`, `deciderAuthMethod`, `resolutionType`, `attributionConfidence`, `scope`.
2. Copy each listed field whose value is neither `undefined` nor `null`. Skip the others entirely. This is why absent and null are the same thing in a payload, and why `deciderAuthMethod` and `resolutionType` are missing rather than null on some receipts.
3. Serialize `Date` values as ISO 8601 UTC with milliseconds. All other values are copied as they are: `receiptVersion` stays an integer, `requestJson` and `reasonCodes` stay strings.
4. Sort object keys lexicographically, recursively. (The payload is flat; the recursion matters for implementations that canonicalize nested objects.)
5. Serialize with `JSON.stringify` semantics: no whitespace, standard JSON string escaping.
6. UTF-8 encode. These are the **canonical bytes**. The issuer stores them as `signedPayloadBytes` and publishes them as `payload_bytes_b64`.

`jcs_v2` differs from `jcs_v1` only in the field list (step 1). Steps 2 through 6 are identical, and a `jcs_v1` receipt verifies forever under its own list. Both lists are frozen: a new signed field requires `jcs_v3` (see `VERSIONING.md`).

## 5. Signing and keys

### 5.1 Algorithm and message

`signatureAlg` is `ed25519` (RFC 8032). **The Ed25519 message is the 32-byte SHA-256 digest of the canonical bytes**, not the canonical bytes themselves. The issuer computes `digest = SHA-256(canonicalBytes)`, signs `digest`, stores the hex digest as `signedPayloadHash`, and publishes it as `signed_payload_hash`. A verifier recomputes the digest from the bytes, compares it to the published hex, and verifies the signature over the digest.

The signature is 64 raw bytes, Base64-encoded in `signature_b64` (and in the stored `signatureValue`).

### 5.2 Key identification

Every payload names its key in `signatureKeyId`; the artifact repeats it as `key_id`. Verifiers MUST resolve the public key by that id and MUST NOT assume a single current key. Verifiers MUST reject an artifact whose `key_id` disagrees with the `signatureKeyId` inside the signed bytes.

### 5.3 Public key distribution

The issuer publishes its key set at:

```
https://app.permissionprotocol.com/.well-known/permission-protocol/keys.json
```

```json
{
  "issuer": "https://app.permissionprotocol.com",
  "keys": [
    { "key_id": "pp_key_348f56d61d0deab4", "alg": "ed25519",
      "public_key_b64": "DrIEo9bhRbEZQGFxEujYS7xQ+DkG7VhNkWJ6fOZpRQQ=",
      "status": "active", "created_at": "2026-03-10T17:44:20.810Z", "revoked_at": null }
  ]
}
```

`public_key_b64` is the **raw 32-byte** Ed25519 public key, Base64-encoded. To load it with a library that expects SubjectPublicKeyInfo, prefix the DER header `302a300506032b6570032100` (hex) to the 32 bytes. The same keys are also served one at a time at `GET /api/v1/keys/current` and `GET /api/v1/keys/<keyId>` in a camelCase shape (`keyId`, `algorithm`, `publicKey`, `status`, `createdAt`).

Key `status` is `active` (signs new receipts), `rotated` (verifies old receipts, signs nothing), or `revoked`. Verifiers MUST fail on `revoked` and SHOULD accept `rotated`. Verifiers SHOULD cache the key set and MAY pin a copy; `test-vectors/live-keys.json` is such a copy, dated. Rotation is a procedure the issuer documents; as of this writing no key has been rotated and the mechanism has not been exercised in production.

Demo receipts (`scope: demo`) are signed under a separate demo key, key id `pp-demo-k1`, which the issuer publishes alongside production keys. Its presence in a receipt is itself the demo marker; the `scope` field states it in words.

### 5.4 Signing modes and fail-closed behavior

The issuer runs in `required` mode in production: an `APPROVED` decision that cannot be signed is not written. A `DENIED` decision that cannot be signed is written unsigned and reads as unverified on every public surface; a denial can never authorize anything, so this preserves the audit trail without crossing a boundary. Pending holds are never signed. An unsigned `APPROVED` row is rejected by the issuer's own verifier as a critical fault.

### 5.5 Errata to `RECEIPT-FORMAT-V1.md`

Two statements in the v1 document never matched the product, and independent implementers following it would have produced verifiers that fail on every real receipt:

1. Section 5.1 of v1 says the signed message is the canonical UTF-8 bytes. The issuer has always signed the **SHA-256 digest** of those bytes (5.1 above). The v1 fixtures in `fixtures/` were signed over raw bytes and therefore verify only with verifiers built to the v1 text, such as `pp-cli`; they do not represent issued receipts.
2. Section 3 of v1 types `requestJson` as an object, `reasonCodes` as an array, and `receiptVersion` as the string `"v1"`. The issuer has always stored and signed `requestJson` and `reasonCodes` as **strings** and `receiptVersion` as an **integer** (`1`, then `2`).

The v1 field list itself (the 18 names) and the canonicalization steps were correct. Receipts with `canonicalization: jcs_v1` exist and verify under the v1 field list with the digest message and the string types described here.

## 6. Artifact and verification

### 6.1 The artifact envelope

The portable form of a receipt. Served publicly at `https://app.permissionprotocol.com/r/<receipt_id>.json` for receipts whose signature is intact, and to the owning tenant with an API key holding the `receipts.verify` scope at `GET /api/v1/receipts/<receipt_id>/artifact`. `schema/artifact.json` describes it.

```json
{
  "artifact": {
    "receipt_id": "rcpt_dg_cmt3gkieg0003v5cwonna8pk5",
    "status": "APPROVED",
    "receipt_version": 2,
    "canonicalization": "jcs_v2",
    "key_id": "pp_key_348f56d61d0deab4",
    "alg": "ed25519",
    "signed_payload_hash": "aa4729afd171817a690ab21ae46e16888a854a20c4096f778bc1e6ccbdaccc69",
    "signature_b64": "h3v1UqFVSeS68d3uPTTQj0LQxs4Olqr4Mnn0wesA0kRiSekHSEKVM0rx5U8xLdq9IP8n4nh7xUva7bdUWNwzDg==",
    "payload_bytes_b64": "eyJhZ2VudElkIjoiZ2l0aHViLWFjdGlvbnMi...",
    "issued_at": "2026-08-21T22:26:38.587Z",
    "expires_at": "2026-08-21T22:41:38.565Z",
    "redeemed_at": "2026-08-21T22:27:10.412Z"
  },
  "keys_url": "https://app.permissionprotocol.com/.well-known/permission-protocol/keys.json"
}
```

Only `payload_bytes_b64` and `signature_b64` are authenticated, through the key named by `key_id`. `status`, `issued_at`, `expires_at`, and `redeemed_at` on the envelope are conveniences that MUST agree with the signed payload where they overlap and MUST NOT be trusted on their own.

### 6.2 Verify procedure

A conformant verifier performs these steps in order and stops at the first failure.

1. Parse the envelope. Require `artifact.receipt_id`, `key_id`, `alg`, `signed_payload_hash`, `signature_b64`, `payload_bytes_b64` as strings; require `alg` to be `ed25519`. Otherwise **malformed**.
2. Base64-decode `payload_bytes_b64`. Compute `SHA-256` over the bytes. If the lowercase hex digest differs from `signed_payload_hash`: **payload hash mismatch**.
3. Parse the bytes as JSON. Require an object whose `signatureKeyId` equals `key_id`. Otherwise **malformed**.
4. Re-canonicalize the parsed object under its own `canonicalization` (section 4). If the result differs from the decoded bytes: **canonical mismatch**. The bytes were not produced by this specification.
5. Resolve the public key for `key_id` from the key set. Missing: **key not found**. `status: revoked`: **key revoked**.
6. Base64-decode `signature_b64`; require 64 bytes. Verify Ed25519 over the 32-byte digest from step 2 with the resolved key. Failure: **signature invalid**.
7. Report success with the decoded payload. Report `status` and the decider fields to the caller. Report expiry (`expiresAt` before now) as information, not as a verification failure.

`tools/verify.mjs` implements exactly this and exits `0` verified, `1` signature invalid, `2` key not found or revoked, `3` malformed, `4` hash or canonical mismatch.

### 6.3 Schema validation

After step 7 a verifier SHOULD validate the payload against `schema/receipt-v2.json` and check that `requestJson` parses to an object equal to its own canonical serialization and that `reasonCodes`, when present, parses to an array of strings. A schema failure on a receipt that passed step 6 is a policy failure (an unexpected value, an unknown decider form), not a signature failure, and SHOULD be reported as such.

### 6.4 What verification proves

Success proves that the bytes were signed by the holder of the private key for `key_id` and are unchanged, and therefore that the decision, decider, policy version, action snapshot, and timestamps inside them are what the issuer committed to.

It does not prove that the action executed or succeeded (section 3.2), that the decision was correct, that the receipt is still redeemable, or that the receipt covers the action in front of you unless you compared `requestJson` and `inputHash` to it (section 3.3).

### 6.5 Denials

A `DENIED` receipt verifies with the same procedure. Authenticity and outcome are separate axes: the issuer's public surfaces render a signed denial as an **authentic signature with a DENIED decision**, never as an authorization and never as a failure to verify. Verifiers SHOULD keep the same separation.

### 6.6 Online surfaces

`https://app.permissionprotocol.com/r/<id>` runs the issuer's full verification on every view and withholds a receipt whose bytes do not match its signature. `GET /api/v1/public/receipts/<id>` returns public fields with a `verification` block (`verified`, `signature_intact`, `signature_status`, `state`). `POST /api/v1/receipts/verify` is the tenant-authenticated endpoint CI gates use; it adds scope matching and atomic one-time redemption on top of the cryptographic check.

## 7. Decision and decider semantics

### 7.1 Decisions

`status` is `APPROVED` or `DENIED`. Nothing else is signed. `APPROVED` means the action was authorized under the stated policy version, by the stated decider, at the stated time, for the snapshot in `requestJson`. `DENIED` means it was refused, by policy or by a human, and is signed with the same ceremony. Pending holds (`REQUIRES_APPROVAL`, `REQUIRES_FOUNDER_VETO`), `EXPIRED`, and `ERROR` are lifecycle states of the issuer's row; they carry no signature and are not receipts under this document. (`ALLOW` and `DENY` are the raw vocabulary of the older ledger lane, which is not routed today; verifiers MAY accept them as aliases but will not encounter them from the hosted service.)

### 7.2 Decider identifiers

Every form of `deciderId` the hosted service writes, with the lane and the other attribution fields it comes with:

| `deciderId` | Lane | `deciderAuthMethod` | `attributionConfidence` | `resolutionType` | Meaning |
|---|---|---|---|---|---|
| `user:<userId>` | deploy gate (session or CLI) | `session` | `credentialed` | `allow_once` | A human, authenticated by session, resolved to an owner or admin of the tenant. `deciderDisplay` is the GitHub login. **Names a human.** |
| `api_key:<keyId>` | deploy gate (API key) | `api_key` | `credentialed` | `allow_once` | A machine credential holding the approval scope. Not a human. |
| `demo:<actorId>` | public demo | `anonymous_demo` | `unattributed` | `allow_once` or `deny` | The anonymous public demo signer. Always `scope: demo`, always the demo key. |
| `system/pp-engine` | deploy gate, webhook auto-clearance | absent (null) | `credentialed` | `allow_once` | The policy engine cleared the change on push under `deploy-gate-v1`. No human approved. |
| `system/pp-permission-router` | execute lane | `policy` | `credentialed` | absent | The router's policy evaluation cleared or denied the action, including kill-switch denials. No human approved. |
| `system/pp-policy-engine` | ledger lane (not routed today) | `policy` | `credentialed` | absent | The PPv1 engine. Listed for completeness. |
| `user:<userId>` | execute lane | `session` | `heuristic` | `allow_once` or `deny` | A human resolved the hold in the approvals surface, bound as the individual since 2026-09-08. `deciderDisplay` is the GitHub handle. **Names a human.** `heuristic`, not `credentialed`, because the identity is read from the approval record at signing time rather than captured at the moment of signature: see 7.3 and 7.4. |
| `role/human-approver` | execute lane | `session` | `heuristic` | `allow_once` or `deny` | A human resolved the hold. Every execute-lane human decision before 2026-09-08 carries this, and so does one after that date whose approval record names no resolvable individual: see 7.4. |
| `role/founder` | execute lane | `session` | `heuristic` | `allow_once` or `deny` | As above, for a hold flagged as a founder veto (`FOUNDER_VETO_REQUESTED` in `reasonCodes`). Since 2026-09-08 such a decision binds `user:<userId>` instead and the founder marker stays in the signed `reasonCodes`. |
| `role/api-key-approver` | execute lane | `api_key` | `heuristic` | `allow_once` or `deny` | The hold was resolved with an API key. Not a human. |

**Dated note, 2026-09-08.** Execute-lane human decisions now bind the individual (`user:<userId>`, GitHub handle in `deciderDisplay`, `attributionConfidence: heuristic`). Shipped in `permission-protocol/app` as ADR 0002, `docs/adr/0002-decider-attribution-execute-lane.md`. Receipts signed before that date bind a role class and are never re-signed, so a verifier will meet both forms and must accept both. The API-key lane on the execute path still binds `role/api-key-approver`, because the approvals routes do not learn which key approved. Nothing about the signed field set, the canonicalization, or the vectors changes: `deciderId` was always a string and the schema always accepted this form.

To an assessor, every `system/*` decider is a signed statement that **no human approved this**: the action cleared or was refused deterministically under the recorded `policyVersion`, which is the accountable authority. An auto-clearance can therefore never be mistaken for a human signature, nor a human decision for an automatic one.

### 7.3 Attribution confidence

- `credentialed`: the decider authenticated to the issuer at decision time (session, API key) or is a named policy version. The proof strength of a `session` decider equals the issuer's login: today a GitHub OAuth session resolved to tenant membership, with no re-authentication at the moment of signing. Step-up authentication at signing is designed and not shipped; when it ships it appears as a new `deciderAuthMethod` value, not a new field.
- `heuristic`: the identity was joined from the approval record at signing time rather than captured at the signature. This is the execute lane today (7.4).
- `unattributed`: anonymous. Permitted only in `demo` scope; the issuer refuses to sign an unattributed production decision.

### 7.4 Human signer granularity, stated plainly

On the **deploy-gate lane**, the receipt names the human: `user:<id>` with the GitHub login in `deciderDisplay`, inside the signed bytes. The production receipt in `test-vectors/live-deploy-gate-approve.json` is one.

On the **execute lane**, the receipt names the human as well, since 2026-09-08: a human decision binds `user:<id>` with the GitHub handle in `deciderDisplay`, taken from the approval record the approvals endpoint authenticated and wrote. `attributionConfidence` is `heuristic` rather than `credentialed`, and the distinction is the point: the identity is joined from that record when the receipt is signed, which happens when the agent re-executes, not captured from a live credential at the moment of signature the way the deploy-gate lane captures it inside its signing transaction. Reading `heuristic` as a weaker claim about the same fact is correct. Promoting this lane to `credentialed` requires signing the authorization at the approval decision itself, which is ADR 0003 in `permission-protocol/app` and is not shipped.

Two forms therefore remain in circulation on this lane, and a verifier must accept both. Execute-lane receipts signed before 2026-09-08 bind a role class (`role/human-approver`, `role/founder`) and are never re-signed. After that date a role class still appears when the approval record names no resolvable individual, and the API-key lane still binds `role/api-key-approver`, since the approvals routes do not learn which key approved.

A claim that a receipt "names the human" is now true of both the deploy-gate lane and the execute lane, at the confidence each records. It is not true of MCP Guard's local approvals.

MCP Guard, the open-source proxy, signs its own local receipts with a per-install development key and is not described by this document.

### 7.5 Known windows

Founder-veto denials on the execute lane between 2026-08-11 and 2026-08-12: the signed decider was correct (`role/founder`) but the API's live-recomputed `approver` field read `human` because the deny transition dropped the marker from `reasonCodes`. Fixed forward-only on 2026-08-12; receipts from the window were not re-signed. Trust the signed bytes.

## 8. Chaining: `prev` is reserved

Buyers asked for tamper-evident logs. A signed receipt proves **alteration**: change a byte and the signature fails. It does not prove **omission**: a receipt that was never shown to you leaves no trace in the receipts you were shown. Hash-chaining closes that gap. Each receipt would carry `prev`, the SHA-256 digest of the canonical bytes of the previous receipt in the same tenant stream (or per-gate stream), inside the signed set. A verifier holding a contiguous run can then detect a missing or reordered receipt, and a periodically published checkpoint lets an auditor confirm a stream's head.

`prev` is **reserved** for the next canonicalization version and is not emitted today. Evaluated for this document and deferred, because adding it touches more than this repository can carry:

- A new signed field means `jcs_v3` and a new column on the issuer's receipt row (a schema migration), plus a signer change to read the tenant's previous head under the same transaction that mints the new receipt, plus a decision on stream granularity and checkpoint venue that is an open question for the founder.
- Every verifier, this repository's vectors, and the issuer's own re-canonicalization on verify would change with it.

The issuer's `idemKey` uniqueness per tenant and its append-only row model are not a substitute: they are issuer-side properties a verifier cannot check. Tracked as an issue in this repository; see `VERSIONING.md` for how the field will be introduced.

## 9. Lifecycle around the receipt

- **Expiry.** `expiresAt` bounds redemption of an approval by a CI gate or an agent retry. It does not expire the evidence; an expired receipt still verifies.
- **Redemption.** The issuer's verify endpoint can redeem an approval atomically once. Redemption state is unsigned issuer metadata.
- **Idempotency.** A resubmitted execute-lane request with the same `idemKey` returns the existing receipt; a `DENIED` receipt is terminal for its key (kill-switch denials say so in `reasonCodes` with `KILL_SWITCH_DENIAL_TERMINAL`). A changed action under a reused key is refused with a fresh `DENIED` receipt (`APPROVAL_ARTIFACT_MISMATCH`).
- **Re-approval.** An expired deploy-gate approval can be renewed for the unchanged scope; the renewal is a new receipt with its own id and `DEPLOY_GATE_REAPPROVED` in `reasonCodes`, signed by the renewing decider.

## 10. Security considerations

- **Replay.** A valid signature does not prove the receipt is for the action in front of you. Compare `requestJson` and `inputHash` to your own canonical input, and use `idemKey` or the issuer's redemption for one-time execution.
- **Unsigned metadata.** Anything outside section 3.1 is mutable. Do not decide anything from it.
- **Key compromise.** The issuer holds one production signing key per deployment in environment configuration; its compromise would forge receipts for every tenant until revocation. Verifiers MUST honor `revoked` and SHOULD re-fetch the key set periodically.
- **Canonicalization drift.** Any change to the bytes breaks every existing signature. Implementers MUST test against `test-vectors/` and the live vector; step 4 of the verify procedure exists to catch drift on the issuer's side too.
- **Time.** Expiry comparisons depend on the verifier's clock. Treat expiry as information about redemption, not as a signature property.
- **Demo scope.** Never accept `scope: demo` or key id `pp-demo-k1` as production evidence, whatever the rest of the receipt says.

## 11. Conformance

`test-vectors/` holds:

| File | What it is | Expected result |
|---|---|---|
| `approve-human-deploy-gate.json` | `APPROVED` by a session-authenticated human on the deploy-gate lane, `user:<id>` | verifies |
| `approve-policy-execute-lane.json` | `APPROVED` by the policy engine on the execute lane, read-only tier | verifies |
| `deny-kill-switch-execute-lane.json` | `DENIED` under a global freeze before policy evaluation, terminal for its key | verifies, decision `DENIED` |
| `tampered-approve-human-deploy-gate.json` | vector 1 with `summary` edited after signing and the hash recomputed | fails at the signature |
| `live-deploy-gate-approve.json` | a real production receipt captured from the public artifact endpoint on 2026-09-08 | verifies against `live-keys.json` |
| `keys.json`, `live-keys.json` | the key sets, in the published shape | |

The three generated vectors are produced by `tools/generate-vectors.mjs` from fixed inputs with the repository's test key; CI regenerates them and fails on drift. Their bytes were checked byte for byte against the issuer's own canonicalization code. An implementation claims conformance to this document when it reproduces every expected result above, passes `node --test "test/*.test.mjs"`, and validates each verified payload against `schema/receipt-v2.json`.

## 12. Relationship to other documents

- `RECEIPT-FORMAT-V1.md`: frozen, with errata in 5.5.
- `VERIFY.md`: the nine-line verification and the online paths.
- `MAPPINGS.md`: which fields back which controls.
- `VERSIONING.md`: how this format changes.
- In `permission-protocol/app`: `docs/receipt-standard.md` (the SDK-facing receipt object and status mapping), `permission-protocol-sdk/spec/hashable-payload-v1.md` (`inputHash` on the execute lane), `src/lib/permission-protocol-v1/signing/canonicalize.ts` (the frozen field lists this document transcribes).
