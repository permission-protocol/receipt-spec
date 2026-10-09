# Permission Protocol Receipt Format, as emitted

**Version markers covered:** `receiptVersion` `2`, `canonicalization` `jcs_v2`; and `receiptVersion` `3`, `canonicalization` `jcs_v3` (sections 3.4 to 3.8 and 6.7). **Status:** the `jcs_v2` text describes what the hosted service at `app.permissionprotocol.com` has issued since 2026-07-09, traced field by field to the code that writes it. `jcs_v3` has been issued by the hosted service since 2026-10-08, when its switch (`PP_RECEIPT_V3`) was turned on in production (issuer pull requests `permission-protocol/app#614`, mint, and `#616`, read side). It was turned on before this text was merged, so `VERSIONING.md` records the date. Production `jcs_v3` receipts verify with `tools/verify.mjs` at this revision (section 12). **Date:** 2026-09-08; `jcs_v3` sections 2026-10-06; the `deploy_gate/v2` projection 2026-10-08. **License:** CC BY 4.0 for this text; Apache-2.0 for the schemas, vectors, and tools.

This document supersedes `RECEIPT-FORMAT-V1.md` as the description of the current format. The v1 document stays in this repository unchanged, because it is what `jcs_v1` receipts were published against; section 5.5 records where it disagreed with the product.

## 1. Purpose and scope

A receipt is a signed statement that one decision was made about one gated action: approved or denied, by whom, under which policy version, at what time, against which exact action snapshot. It is issued by the system that made or recorded the decision and verified by anyone holding the issuer's public key. It proves authorization. It does not prove that the action ran, that it succeeded, or that the decision was wise.

In scope: the signed payload (section 3; for `jcs_v3`, the request commitment and public projection that replace the request and the summary in the signed bytes, and the signed decider proof, sections 3.4 to 3.8), how its bytes are built (section 4), how they are signed and how keys are found (section 5), the portable envelope and the verify procedure (section 6), and what the decision and decider fields mean (section 7).

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
- **Revocation**: the withdrawal of an unused deploy-gate approval. The issuer signs it as a `DENIED` receipt of its own (`rcpt_rev_<uuid>`); `jcs_v3` treats revocations as a lane with their own projection (section 3.7).
- **Committed request** (`jcs_v3`): the issuer's private action snapshot, `requestJson`, bound into the signature through a salted commitment (section 3.5) instead of being carried in the signed bytes. It also carries the receipt's binding to its workspace and idempotency record, under the reserved key `receiptBinding`, and its summary, under the reserved key `receiptSummary`.
- **Public projection** (`jcs_v3`): the part of the committed request that the allowlist of the receipt's lane makes public, signed as `publicProjectionJson` (section 3.6). Its **projection tag** names the allowlist and its version: `deploy_gate/v1`, `deploy_gate/v2`, `execute/v1` or `revocation/v1` (section 3.7).
- **Decider proof** (`jcs_v3`): the evidence of a decider's step-up at signing, a passkey assertion or a recent re-authentication, signed as `deciderProof` (section 3.8).
- **Opening** (`jcs_v3`): presenting the exact request text and the salt that reproduce a commitment (section 6.7).

## 3. Data model

### 3.1 The signed payload

This section is the `jcs_v2` field set (`receiptVersion` 2). `jcs_v3` signs a different set, derived from this one: section 3.4.

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
| `reasonCodes` | string | optional | A JSON array of strings, serialized as text. Order preserved. Examples: `["DEPLOY_GATE_APPROVED"]`, `["READONLY_OPERATION"]`, `["GLOBAL_FREEZE_ACTIVE","KILL_SWITCH_DENIAL_TERMINAL"]`, `["APPROVAL_DENIED","FOUNDER_VETO_REQUESTED"]`. A deploy-gate policy denial has named its rule as the second code (`["DEPLOY_GATE_DENIED","deny.deterministic_dangerous_diff"]`); from the change that moves the deploy-gate lane to `deploy_gate/v2` on, it does so only when the request records a public repository (3.4). |
| `summary` | string | optional | Human-readable summary of the decision context. Signed under `jcs_v1` and `jcs_v2`; `jcs_v3` commits it inside the request instead (3.5). |
| `deciderId` | string | always (v2) | Stable id of who decided. Section 7.2 lists every form in use. |
| `deciderDisplay` | string | always (v2) | Human-facing label: the GitHub login for a session signer, a fixed label for the policy engine, a role-class label on the execute lane. |
| `deciderAuthMethod` | string | optional (v2) | `session`, `session_stepup_webauthn`, `session_reauth`, `api_key`, `anonymous_demo`, or `policy`. The two step-up values name a human who gave fresh proof of presence at the moment of signing (a passkey assertion, or a recent re-authentication) on top of the session; `jcs_v3` also signs that evidence, `deciderProof` (3.8). Absent where the mint path recorded null: the deploy-gate webhook auto-clearance (`system/pp-engine`). |
| `resolutionType` | string | optional (v2) | `allow_once`, `allow_always`, or `deny`. Absent on policy-engine decisions on the execute and ledger lanes: the engine cleared or denied under policy, it did not allow once. |
| `attributionConfidence` | string | always (v2) | `credentialed`, `heuristic`, or `unattributed`. Section 7.3. |
| `scope` | string | always (v2) | `production` or `demo`. A demo receipt is signed under a distinct demo key and can never pass as production evidence. |
| `receiptVersion` | integer | always | `2`. An integer, not a string. |
| `canonicalization` | string | always | `jcs_v2`. |
| `signatureAlg` | string | always | `ed25519`. |
| `signatureKeyId` | string | always | Names the issuer key. Resolve it through the published key set before verifying. |
| `expiresAt` | string | always | ISO 8601 UTC with milliseconds (`Date.prototype.toISOString`). Bounds one-time redemption of an approval (deploy gate: 15 minutes by default; execute lane: one hour, or 15 minutes for an authorization signed before execution, section 9). The signature stays valid evidence after expiry. |
| `createdAt` | string | always | ISO 8601 UTC with milliseconds. When the row was created. Decision receipts on both lanes are signed when the decision lands, so for those it is also the decision time. |

`schema/receipt-v2.json` encodes this table. It marks `additionalProperties: false`: a payload carrying any other key was not produced under `jcs_v2`.

### 3.2 Fields the signature does not cover

The issuer stores more than it signs. `signatureValue`, `signedPayloadBytes`, `signedPayloadHash`, `signerOrigin`, `redeemedAt`, `redeemedRunId`, `redeemedBy`, `approvalId`, `linkedApprovalId`, `policySnapshotBefore`, `policySnapshotAfter`, `executionJson`, `errorJson`, `receiptType`, and `updatedAt` are outside the signed set. In particular:

- **Execution outcome is not in the receipt.** `executionJson` and `errorJson` record what a tool returned on the execute lane; they are unsigned issuer data and may be absent. A receipt proves authorization, not completion. The outcome, when the issuer recorded one, is a separate signed object that references the receipt: the execution attestation (section 9).
- **Redemption is issuer state.** One-time redemption (`redeemedAt`) is enforced by the issuer's verify endpoint for CI gates. It is not evidence and it is not signed.

Under `jcs_v3` (section 3.4) five more stored fields fall outside the signed set: `companyId`, `idemKey`, `requestJson`, `inputHash` and `summary`. The signature still binds `requestJson`, through `requestCommitment`, and the summary through the same commitment, because the committed request carries it (3.5). The salt that opens that commitment (`requestCommitmentSalt`, 32 bytes) is stored beside the receipt, is never signed, and is never placed on a public surface. The issuer stores a signed `deciderProof` as its canonical text, in a column of another name (`deciderProofJson`); the object is what the bytes carry (3.8).

### 3.3 `requestJson`

`requestJson` is the exact action the decider saw, serialized once by the issuer with recursively sorted keys and no whitespace, then stored and signed as a string. Signing the string rather than an embedded object is deliberate: the bytes cannot drift with a re-serialization.

Its contents are lane-specific and issuer-defined. Verifiers MUST treat `requestJson` as authenticated **text** and MAY parse it for display or scope checks. The two shapes today:

- Deploy gate: `{ action: { operation: "deploy", tool: "github-actions" }, context: { environment, reversibility: "REVERSIBLE" }, enrichmentSnapshot, intent: { category: "deployment", name: "deploy_gate_approval", summary }, metadata: { deployGateRequestId, ... demo markers when scope is demo }, policy: { decision, expiresAt }, scope: { artifact_digest, capability, commitSha, env, ref, repo, workflow } }`.
- Execute lane: the caller's full request as canonical JSON: `{ action: { operation, parameters, tool }, actor: { agentId, runId }, constraints?, context: { environment, reversibility, ... }, hashes: { inputHash }, intent: { category, name, summary }, tenantId }`.

A verifier checking that a receipt covers the action in front of it compares the fields it cares about (repository, commit, tool, parameters) against the parsed `requestJson`, and the digest of its own canonical input against `inputHash`.

Under `jcs_v3`, `requestJson` is not in the signed bytes. The issuer stores it as canonical text (sorted keys, no whitespace) and signs a commitment to it (3.5) and a projection of it (3.6). The stored text is the committed request: the request the mint path built, plus the receipt's binding under the reserved key `receiptBinding` and its summary under the reserved key `receiptSummary` (3.5).

### 3.4 The `jcs_v3` signed payload (`receiptVersion` 3)

A receipt link travels well beyond the workspace that owns it: pull-request comments and commit statuses, notifications, forwarded messages. The public artifact carries the signed bytes, so under `jcs_v2` those bytes publish the request itself: repository names, changed paths, model-written descriptions of a private change, an agent's parameters, and the free-text summary. `jcs_v3` signs a salted commitment to the request, with the summary and the receipt's workspace and idempotency binding committed inside it, and an allowlisted projection of the request instead. It is designed so that its signed bytes carry nothing the public receipt page does not show, while the signature still binds exactly one request, one summary and one workspace. It also signs the evidence of a decider's step-up at signing (3.8).

The `jcs_v3` signed field set has 22 fields and is frozen. In canonical (sorted) order:

`agentId`, `attributionConfidence`, `canonicalization`, `createdAt`, `deciderAuthMethod`, `deciderDisplay`, `deciderId`, `deciderProof`, `expiresAt`, `id`, `policyVersion`, `publicProjectionJson`, `reasonCodes`, `receiptVersion`, `requestCommitment`, `resolutionType`, `riskTier`, `runId`, `scope`, `signatureAlg`, `signatureKeyId`, `status`.

Relative to `jcs_v2`:

| Change | Field | Type, presence | Why |
|---|---|---|---|
| removed | `companyId` | | The tenant id links one workspace's receipts across repositories. Committed inside the request under `receiptBinding` instead (3.5). |
| removed | `idemKey` | | Deploy gate: embeds the unsalted scope hash. Execute lane: the caller's free-text idempotency key, or else the unsalted `inputHash`. Committed under `receiptBinding` (3.5). |
| removed | `requestJson` | | The private request. Committed and projected instead. |
| removed | `inputHash` | | An unsalted hash over the request or its scope confirms a guessed repository, recipient or parameter. Committed under `receiptBinding` (3.5). |
| removed | `summary` | | Free text: a decider's typed reason, an override justification, a revocation reason, or a model-written description of a private change on a clearance. Committed inside the request under `receiptSummary` instead (3.5). |
| added | `requestCommitment` | string, always | `sha256:` plus 64 lowercase hex: a salted commitment to the exact `requestJson` text, which carries the binding and the summary (3.5). |
| added | `publicProjectionJson` | string, always | Canonical JSON text of the public projection of `requestJson`, naming its tag (3.6, 3.7). |
| added | `deciderProof` | object, present exactly when `deciderAuthMethod` is `session_stepup_webauthn` or `session_reauth` | The evidence of the decider's step-up at signing, in one of two frozen shapes (3.8). |

The other 19 fields keep the types and meanings of section 3.1, except that `receiptVersion` is the integer `3` and `canonicalization` is `jcs_v3`. Every `jcs_v3` receipt signs a decider: `deciderId`, `deciderDisplay`, `attributionConfidence` and `scope` are always present. Every signed field name equals the issuer's stored column name except `deciderProof`, which the issuer stores as its canonical text in `deciderProofJson`. `schema/receipt-v3.json` encodes this table with `additionalProperties: false`. `jcs_v3` carries no chain field (section 8).

**Which receipts are `jcs_v3`.** Once the issuer turns `jcs_v3` on, every mint path with a projection tag signs it: the deploy-gate lane (human approve and deny, webhook clearance and policy denial, re-approval, carry-forward, denial repair, policy override, demo approve and deny, merged-PR deployment renewal), the execute lane, and revocations. The deploy-gate lane signs `deploy_gate/v2` from `permission-protocol/app#691` on, and `deploy_gate/v1` before it (3.7). The ledger lane, which is not routed today, has no tag and keeps signing `jcs_v2`. Receipts already signed under `jcs_v1` or `jcs_v2` keep their bytes and verify under their own rules forever; nothing is re-signed, rewritten or migrated (`VERSIONING.md`).

**`summary` is committed, not signed.** The summary is the decision's stated reason. It can carry text a decider typed (an approval or denial reason, an override justification, a revocation reason) and, on a deploy-gate webhook clearance, the model-written description of the change. Under `jcs_v3` it is neither a signed field nor part of the public artifact. The issuer's mint commits it inside the request (3.5), so the signature binds it for whoever opens the commitment, and nobody else learns it. The issuer keeps storing the summary beside the receipt for the workspace's own surfaces; a summary shown for a `jcs_v3` receipt is unsigned issuer data until an opening checks it (section 6.7, step 3).

**`companyId`, `idemKey` and `inputHash` are committed, not signed.** Under `jcs_v2` the signature bound each receipt to its workspace (`companyId`) and to its idempotency record (`idemKey`, `inputHash`): an edit to any of the three stored columns broke the signature. The issuer relies on those columns. Its reads and verifications filter receipts by workspace, a resubmitted execute-lane request returns the receipt stored under the same `idemKey`, and a deployment renewal compares the previous receipt's `inputHash` with the scope it renews. One issuer key signs for every workspace, so a signature that covers none of the three does not say which workspace a receipt belongs to. `jcs_v3` keeps them out of the public bytes for the reasons in the table above, and binds them inside the commitment instead, under `receiptBinding` (3.5). The issuer checks its stored values against the committed ones on every verification it performs; a third party learns none of them.

**`reasonCodes` are public.** A `jcs_v3` receipt signs `reasonCodes` in its public bytes, beside the projection, so a code must not publish what the projection withholds. Three deploy-gate mint paths name the matched policy rule in their codes: a policy denial and a denial repair (`DEPLOY_GATE_DENIED`), and a policy override (`DEPLOY_GATE_POLICY_OVERRIDE`). They sign `[code, ruleId]` only when the committed request records `scope.visibility` exactly `"public"`, and `[code]` otherwise. This is the ‡ rule of `deploy_gate/v2` (3.6, step 3) applied to the reason codes, and the issuer applies it from the same change that moves the lane to `deploy_gate/v2` (`permission-protocol/app#691`). The rule stays in the committed request either way. Receipts signed before that change, `deploy_gate/v1` ones included, sign `[code, ruleId]` whatever the visibility, and keep their bytes. No verifier check depends on this rule: the projection check reads the projection only.

### 3.5 `requestCommitment`

```
requestCommitment = "sha256:" + lowercase_hex( SHA-256( salt || UTF-8(requestJson) ) )
```

- **`salt`** is 32 bytes from a cryptographically secure random generator, drawn fresh for each receipt and never reused. The fixed length makes the concatenation unambiguous. The issuer stores it beside the receipt; it is not signed and is never published on a public surface.
- **`requestJson`** is the exact stored request text, byte for byte: the committed request, which carries the summary (below). Under `jcs_v3` the issuer stores canonical text (3.3) and refuses to sign anything else. An opening hashes the text as given and never re-serializes it, so a pretty-printed copy of the same object does not open the commitment.
- **Binding** rests on the collision resistance of SHA-256: the signature commits the issuer to exactly one request text. **Hiding** rests on the salt: without it the commitment confirms nothing about a guessed request, which is the property `inputHash` lacked.
- **One salt per receipt**, not per workspace. Two receipts over the same request get unlinkable commitments, and the workspace can open one receipt for an auditor without opening any other.

**The committed summary.** The request the commitment covers carries the receipt's summary. Before it computes the commitment, the issuer's mint adds the summary to the request under the top-level key `receiptSummary` when the summary is a string, and leaves the key out when the receipt has no summary. The result, re-serialized as canonical text, is the stored `requestJson`. The key is reserved:

- A request handed to the mint that already carries `receiptSummary` is refused before anything is signed. Only the mint sets it, and only to a string.
- No projection allowlist names it (3.7), and none ever may, so the summary never reaches the public bytes.

A holder of the request and its salt reads the summary from the opened request. When it also holds the summary the issuer states for the receipt, it checks that the two are equal (section 6.7, step 3).

**The committed binding.** The request the commitment covers also carries the receipt's binding to its workspace and idempotency record, the three fields `jcs_v2` signed and `jcs_v3` does not (3.4). Before it computes the commitment, the issuer's mint adds the top-level key `receiptBinding`:

```json
"receiptBinding": { "companyId": "co_…", "idemKey": "…", "inputHash": "…" }
```

- **Shape.** An object with exactly the keys `companyId`, `idemKey` and `inputHash`. Each value is the receipt's stored value as a string, or `null` when the receipt has none. All three keys are always present: unlike a signed field, a `null` here is kept, never dropped.
- **Always present.** The mint writes it on every `jcs_v3` receipt, with or without a summary. A committed request without it, or with any other shape, is not one the issuer committed.
- **Order.** The mint adds `receiptBinding`, adds `receiptSummary` when the summary is a string, and serializes the result canonically (3.3). Canonical text sorts keys, so the binding reads `{"companyId":…,"idemKey":…,"inputHash":…}` and `receiptBinding` comes just before `receiptSummary`.
- **Reserved.** A request handed to the mint that already carries `receiptBinding` is refused before anything is signed (`REQUEST_RESERVED_KEY`, as for `receiptSummary`). No projection allowlist names it (3.7), and none ever may, so neither the workspace nor the idempotency key nor the input hash reaches the public bytes.

The issuer opens the commitment on every verification it performs. It checks its stored summary against the committed one, and its stored `companyId`, `idemKey` and `inputHash` against the committed binding, each exactly: a stored value that is not the committed one is **receipt binding mismatch**, the stored record changed outside the signature (section 6.7). A holder of the request and its salt reads the binding from the opened request. When it also holds the values the issuer states for the receipt, it checks that each one held equals the committed one (section 6.7, step 3).

The workspace that owns the receipt receives the request text, its salt, the stored summary and the stored binding values through the issuer's authenticated surfaces, under these fields on each `jcs_v3` receipt they carry:

- **`request_json`**: the stored request text, byte for byte (a JSON string whose value is that text).
- **`request_commitment_salt_b64`**: the 32-byte salt, standard base64; `null` when the issuer no longer holds it, in which case the commitment cannot be opened (request commitment unavailable, section 6.7).
- **`summary`**: the receipt's summary as the issuer stores it, or `null` when it has none. Not signed: an opening checks it against `receiptSummary`.
- **`company_id`**, **`idem_key`**, **`input_hash`**: the receipt's `companyId`, `idemKey` and `inputHash` as the issuer stores them, each a string or `null`. Not signed: an opening checks each one present against `receiptBinding`.

These fields appear only on authenticated owner surfaces (the owner artifact and the JSON evidence package), never on the public artifact or a bulk export. On v1 and v2 receipts they are absent or `null`; those receipts sign their request, summary and binding in the bytes. Anyone the workspace gives one receipt's request and salt can open that receipt (section 6.7, step 3).

### 3.6 `publicProjectionJson`

The public projection is a pruned copy of the committed request. The issuer builds it from `requestJson` under the allowlist of the receipt's lane and signs it as JSON **text**, for the same reason it signed `requestJson` as text (3.3). Values keep the paths they have in the request: a reader that took `scope.commitSha` or `policy.decision.ruleId` from a `jcs_v2` `requestJson` reads the same path in a `jcs_v3` projection.

**Build rule.** The projection is a pure function of the tag and the request text:

1. Parse `requestJson`. If it is not a JSON object, there is no receipt: the issuer fails closed before signing.
2. For each path in the tag's allowlist (3.7), in order, copy the value if it is present:
   - `a.b` names key `b` of object `a`. If an intermediate value is absent or is not an object, nothing is copied.
   - `a[].b` applies to an array `a`; if `a` is not an array, nothing is copied. The projection gets an array of the same length with one object per element, and each object receives key `b` of the matching element when that element is an object. An element that receives nothing stays as `{}`, so sibling paths of the same array stay aligned by position.
   - At the last segment, a **value** slot copies a scalar (string, number, boolean or `null`) or an array of scalars unchanged. Any other value, such as an object or an array holding an object, is omitted.
   - An **identifier** slot copies a string only when it matches `^[A-Za-z0-9._:/-]{1,128}$`. A **one of** slot copies a string only when it is one of the listed values. Anything else is omitted, never truncated, so free text never rides in an identifier slot.
   - Nothing is null-filled: an absent path stays absent.
3. Paths marked **†** are repository identity. Paths marked **‡** are policy rule identity: the matched policy rule's id and version, which only `deploy_gate/v2` marks (3.7). Both are copied only when the same request's `scope.visibility` is exactly the string `"public"`; absent or any other value counts as private. The issuer records `scope.visibility` at signing from what GitHub reported for the repository: `public` only when GitHub reported the repository as not private (`private: false`) and its visibility as `public`, `private` for any other answer (an internal repository, a missing or unexpected field), and none when it learned nothing.
4. Remove every object or array that the build created and that received nothing, recursively. Array elements are the exception: they stay as `{}` while any element of the same array received something. An array whose elements all received nothing is removed.
5. Add the top-level key `projection` with the tag as its value, sort keys recursively, and serialize without whitespace (`JSON.stringify` semantics). The result is `publicProjectionJson`.

`tools/public-projection.mjs` implements the rule; section 12 records its byte-for-byte check against the issuer's implementation.

**Tags are frozen.** A tag's allowlist is frozen once a receipt is signed with it, under the same rule as a canonicalization version. A new lane or a changed allowlist is a new tag, as `deploy_gate/v2` is for `deploy_gate/v1` (3.7), not a new canonicalization: the signed field set and the byte rules stay the same. A verifier rebuilds and checks a projection under the tag the projection names, never under the tag its lane signs today. A verifier that does not know a tag fails closed (section 6.7).

### 3.7 Projection allowlists

Each table is normative. It lists every path its tag may publish, in build order, with the slot kind from 3.6 step 2 (**value**, **identifier**, or **one of** the listed strings). † marks repository identity and ‡ policy rule identity (3.6 step 3). `deploy_gate/v2` is stated as its one difference from `deploy_gate/v1`. A path that is not listed is never projected. No allowlist names `receiptSummary` or `receiptBinding`, the reserved keys that carry the committed summary and binding (3.5), and no future tag may.

#### `deploy_gate/v1`

Signed by every deploy-gate mint path listed in 3.4 until the lane moves to `deploy_gate/v2` (`permission-protocol/app#691`): intents `deploy_gate_approval`, `deploy_gate_denial` and `deploy_gate_policy_override`, and the merged-PR deployment renewal. It is frozen. Every receipt signed under it keeps its bytes and verifies under this table, matched rule included, whatever its repository's visibility.

| Path | Slot | † |
|---|---|---|
| `intent.name` | value |  |
| `intent.category` | value |  |
| `action.tool` | value |  |
| `action.operation` | value |  |
| `context.environment` | identifier |  |
| `context.reversibility` | one of `REVERSIBLE`, `PARTIALLY_REVERSIBLE`, `IRREVERSIBLE` |  |
| `scope.env` | identifier |  |
| `scope.capability` | identifier |  |
| `scope.commitSha` | identifier |  |
| `scope.artifact_digest` | identifier |  |
| `scope.visibility` | one of `public`, `private` |  |
| `scope.repo` | identifier | † |
| `scope.ref` | identifier | † |
| `scope.workflow` | identifier | † |
| `policy.expiresAt` | value |  |
| `policy.decision.outcome` | value |  |
| `policy.decision.ruleId` | value |  |
| `policy.decision.ruleVersion` | value |  |
| `policy.decision.matchedInputs.changeClass` | value |  |
| `policy.decision.matchedInputs.analysisComplete` | value |  |
| `policy.decision.matchedInputs.targetBranch` | value | † |
| `policy.decision.matchedInputs.defaultBranch` | value | † |
| `policy.decision.matchedInputs.changedPaths` | value | † |
| `policy.authorizationBinding.version` | value |  |
| `policy.authorizationBinding.path` | value |  |
| `policy.authorizationBinding.commitSha` | value |  |
| `policy.authorizationBinding.rulesHash` | value |  |
| `policy.authorizationBinding.repository` | value | † |
| `policy.authorizationBinding.branch` | value | † |
| `policy.authorizationBinding.prNumber` | value | † |
| `policyAuthorization.version` | value |  |
| `policyAuthorization.evaluatorVersion` | value |  |
| `policyAuthorization.policyBlob` | value |  |
| `policyAuthorization.headSha` | value |  |
| `policyAuthorization.branch` | value | † |
| `policyAuthorization.recordedDecisions[].displayName` | value |  |
| `policyAuthorization.recordedDecisions[].at` | value |  |
| `metadata.deployGateRequestId` | value |  |
| `metadata.denial.category` | value |  |
| `metadata.denial.decisionClass` | value |  |
| `metadata.denial.ruleId` | value |  |
| `metadata.denial.final` | value |  |
| `metadata.denial.requireNewRequest` | value |  |
| `metadata.denial.decidedAt` | value |  |
| `metadata.override.overriddenReceiptId` | value |  |
| `metadata.override.overriddenDecisionClass` | value |  |
| `metadata.override.ruleId` | value |  |
| `metadata.override.ruleVersion` | value |  |
| `metadata.override.deniedAt` | value |  |
| `metadata.override.grantsAuthorization` | value |  |
| `metadata.override.nextState` | value |  |
| `metadata.pullRequest` | value | † |
| `metadata.demo` | value |  |
| `metadata.demoScope` | value |  |
| `metadata.approverDisplayName` | value |  |
| `deploymentRenewal.purpose` | value |  |
| `deploymentRenewal.previousReceiptId` | value |  |
| `deploymentRenewal.mergeCommitSha` | value |  |
| `deploymentRenewal.rulesHash` | value |  |
| `deploymentRenewal.recordedDecisions[].displayName` | value |  |
| `deploymentRenewal.recordedDecisions[].at` | value |  |

The commit SHA, the artifact digest, the policy commit and the rules hash are projected for every repository. They bind the receipt to exact content for anyone who can see the repository, and they reveal nothing to anyone who cannot. For a private repository, the projection does not carry the repository name, ref, workflow, branches, changed paths or pull-request number.

Never projected, so they stay behind the commitment:

- `enrichmentSnapshot`, all of it.
- `intent.summary`.
- From `policy.decision.matchedInputs`: `riskSignals`, `repoPolicy` (the customer's rule rationale and matched files), `approvalRequirements` (approver lists), `ruleEvaluations` and `findings`.
- `metadata.denial.reason` and `.deciderKind`. The signed `deciderId` already names who denied.
- `metadata.override.justification`, `.overriddenDecider`, `.overriddenDeciderKind` and `.deniedGeneration`.
- `policyAuthorization.requirements`, `.binding`, `.repo`, `.round`, `.policyRef`, and `recordedDecisions[].userId` and `.authMethod`.
- `deploymentRenewal.reviewBinding`, an unsalted hash over guessable scope and branch facts, and `deploymentRenewal.recordedDecisions[].userId` and `.authMethod`.
- Every key that is not listed.

A recorded decision is projected as its display name and time, never its auth method. Only the final signer's step-up is signed, as `deciderProof` (3.8). An earlier signer's `authMethod` (for example `session_stepup_webauthn`) would be a public claim of a step-up with no proof behind it, so it stays behind the commitment with the rest of the decision. No `jcs_v3` receipt had been signed when this was decided (2026-10-06), so `deploy_gate/v1` was edited in place, before its first use.

#### `deploy_gate/v2`

Signed by every deploy-gate mint path listed in 3.4 from `permission-protocol/app#691` on. It is specified before the first receipt carries it: every issuer verifier reads it from `permission-protocol/app#688` on, and `VERSIONING.md` will record the date the lane first signs it. Rod decided on 2026-10-08 (design note F-2, question Q-F2-4) to hide a private repository's matched rule ids from the signed public projection, because rule ids can reveal a workspace's internal controls; the owner's evidence keeps them, and receipts already signed stay as they are.

`deploy_gate/v2` is the `deploy_gate/v1` table, path for path, in the same order, with the same slots and † marks. It adds the ‡ mark (3.6 step 3) to exactly these five paths:

| Path | Slot | ‡ |
|---|---|---|
| `policy.decision.ruleId` | value | ‡ |
| `policy.decision.ruleVersion` | value | ‡ |
| `metadata.denial.ruleId` | value | ‡ |
| `metadata.override.ruleId` | value | ‡ |
| `metadata.override.ruleVersion` | value | ‡ |

`ruleVersion` is marked because a customer rule's version is `<rule id>@<policy commit>`. The issuer's built-in rule ids (such as `hold.protected_path` and `deny.deterministic_dangerous_diff`) are withheld too: they say what a private change touched. For a public repository, a `deploy_gate/v2` projection holds exactly what the `deploy_gate/v1` projection of the same request holds; only the tag differs. For any other repository it still carries the decision outcome, the change class, the denial's category, class and finality, the policy commit and the rules hash, and no rule id or version. The rule stays in the committed request (3.5): the workspace reads it, and so does anyone it opens the commitment for (section 6.7, step 3). The same rule governs the deploy-gate reason codes that name a rule (3.4).

#### `execute/v1`

Signed by the execute lane (the permission router's decisions). The four names are typed by the agent, so they are identifier slots. The two context values are the enums the execute API validates.

| Path | Slot | † |
|---|---|---|
| `intent.name` | identifier |  |
| `intent.category` | identifier |  |
| `action.tool` | identifier |  |
| `action.operation` | identifier |  |
| `context.environment` | one of `development`, `staging`, `production` |  |
| `context.reversibility` | one of `REVERSIBLE`, `PARTIALLY_REVERSIBLE`, `IRREVERSIBLE` |  |

Never projected: `tenantId`; `actor` (`agentId` and `runId` are signed top-level fields); `intent.summary`; `action.parameters`; `context.costEstimateUsd`; `context.metadata`; `constraints`, including `idempotencyKey`; `hashes`. The policy version, the expiry, the risk tier and the reason codes on this lane are already signed top-level fields.

#### `revocation/v1`

Signed by revocations. The scope is copied from the revoked receipt's request without its `visibility`. A revocation records `scope.visibility` only from a fresh read of the repository when it is revoked, and none otherwise, so by default its projection carries no repository identity (the † rule treats an absent visibility as private). A repository made private after its approval is therefore never republished by the revocation.

| Path | Slot | † |
|---|---|---|
| `intent.name` | value |  |
| `metadata.revokedReceiptId` | value |  |
| `metadata.deployGateRequestId` | value |  |
| `scope.env` | identifier |  |
| `scope.capability` | identifier |  |
| `scope.commitSha` | identifier |  |
| `scope.artifact_digest` | identifier |  |
| `scope.visibility` | one of `public`, `private` |  |
| `scope.repo` | identifier | † |
| `scope.ref` | identifier | † |
| `scope.workflow` | identifier | † |

Never projected: `metadata.reason` (free text; it is also the summary, committed under `receiptSummary`) and `intent.summary`.

### 3.8 `deciderProof`

A decider whose `deciderAuthMethod` is `session_stepup_webauthn` or `session_reauth` gave fresh proof of presence at the moment of signing. A `jcs_v2` receipt signs only that label. A `jcs_v3` receipt also signs the evidence, as `deciderProof`: a JSON object inside the signed bytes (an object, not text; section 4 sorts its keys). The issuer builds it from the step-up evidence it stored for that decision, copies only the keys listed below, and validates every one; nothing is defaulted or synthesized. Every key is required unless marked optional, and no other key is ever signed.

**`webauthn`**, a passkey assertion, for `session_stepup_webauthn`:

| Key | Type | Rule |
|---|---|---|
| `method` | string | `webauthn` |
| `credentialIdHash` | string | Lowercase hex SHA-256 (64 characters) of the passkey's credential id. |
| `challengeHash` | string | Lowercase hex SHA-256 of the single-use challenge the assertion signed. |
| `authenticatorDataHash` | string | Lowercase hex SHA-256 of the authenticator data the assertion returned. |
| `userVerified` | boolean | Whether the authenticator reported user verification. |
| `rpId` | string | The relying party id, the issuer's host name: `^[A-Za-z0-9.-]{1,253}$`. |
| `origin` | string | The origin the assertion was made from: an `http` or `https` URL, at most 2048 characters, that equals the serialization of its own origin under the URL standard (no path, no trailing slash, lowercase scheme and host, default port omitted). |
| `reviewGeneration` | integer | Optional: the policy review round the assertion was bound to, when the decision recorded one. A positive safe integer (1 to 2^53 − 1). |
| `verifiedAt` | string | When the issuer verified the assertion: an ISO 8601 instant exactly as `Date.prototype.toISOString` writes it (`YYYY-MM-DDTHH:mm:ss.sssZ`, a real calendar date). |

**`reauth`**, a recent re-authentication, for `session_reauth`:

| Key | Type | Rule |
|---|---|---|
| `method` | string | `reauth` |
| `authTime` | string | When the decider last signed in to the issuer's identity provider: an ISO 8601 instant, as `verifiedAt` above. |
| `maxAgeMs` | integer | The freshness window the issuer applied, in milliseconds: a positive safe integer. |
| `verifiedAt` | string | When the issuer accepted the re-authentication for this decision: an ISO 8601 instant. |

and `verifiedAt` minus `authTime`, in milliseconds, is at most `maxAgeMs`. A negative difference, clock skew between the issuer's instances, is allowed, as the issuer's own step-up check allows it.

**Consistency, in both directions.** `session_stepup_webauthn` requires a `webauthn` proof. `session_reauth` requires a `reauth` proof. Every other `deciderAuthMethod`, and an absent one, requires that no `deciderProof` be signed. The issuer refuses to sign a receipt that breaks a rule of this section, and every verifier checks them (section 6.7, step 2).

**Not signed.** The issuer's stored passkey evidence also holds the authenticator's signature counter, the request id the challenge was bound to, and a scope hash. None is signed:

- On the deploy gate the scope hash is an unsalted SHA-256 over repository, ref, workflow, commit, environment, capability and artifact digest. The projection publishes the commit, environment and capability, so a signed scope hash would confirm a guessed private repository name. That is why `jcs_v3` dropped `inputHash`. On the execute lane it is the receipt's own id, already signed.
- The bound request id equals the projected `metadata.deployGateRequestId` on the deploy gate, and is an internal approval id on the execute lane.
- Nothing a verifier holds can check the counter.

The issuer keeps the full evidence beside the decision, for the workspace.

**What it makes public.** Three SHA-256 digests, the issuer's relying party id and origin, whether the user was verified, the step-up instants and the review round. The credential id digest is a stable pseudonym of the signer's authenticator; the signed `deciderId` already names the signer, so it links nothing new. `authTime` says when the signer last signed in, within the freshness window of the decision.

`tools/decider-proof.mjs` implements the shapes, the issuer's builder and the check of section 6.7, step 2.

## 4. Canonicalization (`jcs_v2`, `jcs_v3`)

The signed bytes are built as follows. This is exactly the issuer's procedure; `tools/canonicalize.mjs` is a dependency-free reference implementation that CI checks byte for byte against the vectors and against a live production receipt.

1. Take the frozen signed field list for the receipt's `canonicalization` value. For `jcs_v2` that is the 18 `jcs_v1` fields (`id`, `companyId`, `idemKey`, `agentId`, `runId`, `requestJson`, `inputHash`, `status`, `riskTier`, `policyVersion`, `reasonCodes`, `summary`, `receiptVersion`, `canonicalization`, `signatureAlg`, `signatureKeyId`, `expiresAt`, `createdAt`) plus `deciderId`, `deciderDisplay`, `deciderAuthMethod`, `resolutionType`, `attributionConfidence`, `scope`. For `jcs_v3` it is the 22 fields of section 3.4.
2. Copy each listed field whose value is neither `undefined` nor `null`. Skip the others entirely. This is why absent and null are the same thing in a payload, and why `deciderAuthMethod` and `resolutionType` are missing rather than null on some receipts.
3. Serialize `Date` values as ISO 8601 UTC with milliseconds. All other values are copied as they are: `receiptVersion` stays an integer, `requestJson` and `reasonCodes` stay strings, and a `jcs_v3` `deciderProof` stays an object. Step 2 applies to the listed fields only; inside a nested value nothing is skipped.
4. Sort object keys lexicographically, recursively. (The `jcs_v1` and `jcs_v2` payloads are flat. A `jcs_v3` payload is flat except `deciderProof`, whose keys are sorted the same way.)
5. Serialize with `JSON.stringify` semantics: no whitespace, standard JSON string escaping.
6. UTF-8 encode. These are the **canonical bytes**. The issuer stores them as `signedPayloadBytes` and publishes them as `payload_bytes_b64`.

`jcs_v2` differs from `jcs_v1`, and `jcs_v3` from `jcs_v2`, only in the field list (step 1). Steps 2 through 6 are identical for all three, and every receipt verifies forever under the list its own `canonicalization` names. All three lists are frozen: a new signed field requires `jcs_v4` (see `VERSIONING.md`). Of the three `jcs_v3` additions, `requestCommitment` and `publicProjectionJson` are strings and are copied as they are, as `requestJson` was; `deciderProof` is an object, serialized by steps 4 and 5.

**Unknown versions.** A verifier dispatches on the receipt's own `canonicalization` value. It MUST report a value it does not implement as **canonicalization unsupported**: the receipt is unverifiable by that verifier, not tampered. It MUST NOT re-canonicalize the bytes under another version's list. A `jcs_v3` payload rebuilt under the `jcs_v1` or `jcs_v2` list loses its commitment and projection, so a verifier that fell back would report an intact receipt as tampered.

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

A `jcs_v3` receipt uses the same envelope, with `receipt_version` 3 and `canonicalization` `jcs_v3`. Its payload bytes carry no request content beyond the public projection, no summary and no workspace, so they can be published for every lane. The request, its salt, the stored summary and the stored binding values are not part of the public envelope; the owner surfaces add them (3.5).

### 6.2 Verify procedure

A conformant verifier performs these steps in order and stops at the first failure.

1. Parse the envelope. Require `artifact.receipt_id`, `key_id`, `alg`, `signed_payload_hash`, `signature_b64`, `payload_bytes_b64` as strings; require `alg` to be `ed25519`. Otherwise **malformed**.
2. Base64-decode `payload_bytes_b64`. Compute `SHA-256` over the bytes. If the lowercase hex digest differs from `signed_payload_hash`: **payload hash mismatch**.
3. Parse the bytes as JSON. Require an object whose `signatureKeyId` equals `key_id`. Otherwise **malformed**.
4. Resolve the public key for `key_id` from the key set. Missing: **key not found**. `status: revoked`: **key revoked**.
5. Base64-decode `signature_b64`; require 64 bytes. Verify Ed25519 over the 32-byte digest from step 2 with the resolved key. Failure: **signature invalid**.
6. If the parsed object's `canonicalization` names a version the verifier does not implement: **canonicalization unsupported** (section 4). Stop, and do not report tampering. Otherwise re-canonicalize the parsed object under its own `canonicalization`. If the result differs from the decoded bytes: **canonical mismatch**. The bytes were not produced by this specification.
7. For `jcs_v3`, apply section 6.7. Its checks before step 3 are required. Its step 3 runs when the verifier holds the request and its salt.
8. Report success with the decoded payload. Report `status` and the decider fields to the caller. Report expiry (`expiresAt` before now) as information, not as a verification failure.

The key and the signature (steps 4 and 5) come before the canonicalization (step 6) because neither depends on it. A payload rewritten to name a canonicalization the verifier does not know, with its hash recomputed and any signature, fails as signature invalid or key not found. Only a signature that verifies over an unknown canonicalization is canonicalization unsupported: the issuer signed bytes this verifier cannot read.

`tools/verify.mjs` implements exactly this and exits `0` verified, `1` signature invalid, `2` key not found or revoked, `3` malformed (including request commitment malformed), `4` hash or canonical mismatch, `8` unverifiable here, not tampered (canonicalization unsupported, projection unsupported, request commitment unavailable), `9` policy failure (projection not allowed, decider proof mismatch, decider proof invalid), `10` the private record supplied with the receipt does not match what was signed (request commitment mismatch, committed summary mismatch, receipt binding mismatch, public projection mismatch). Section 6.7 defines the `jcs_v3` codes; each code has one meaning on every surface.

### 6.3 Schema validation

After step 8 a verifier SHOULD validate the payload against the schema for its version (`schema/receipt-v2.json` for `jcs_v2`, `schema/receipt-v3.json` for `jcs_v3`; the latter includes the two `deciderProof` shapes, while the rules that tie the proof to `deciderAuthMethod` and bound a re-authentication's age are section 6.7, step 2). For `jcs_v2` it SHOULD also check that `requestJson` parses to an object equal to its own canonical serialization. For both, it SHOULD check that `reasonCodes`, when present, parses to an array of strings. A schema failure on a receipt that passed step 6 is a policy failure (an unexpected value, an unknown decider form), not a signature failure, and SHOULD be reported as such.

### 6.4 What verification proves

Success proves that the bytes were signed by the holder of the private key for `key_id` and are unchanged, and therefore that the decision, decider, policy version, action snapshot, and timestamps inside them are what the issuer committed to.

It does not prove that the action executed or succeeded (section 3.2; an execution attestation, section 9, records what the issuer observed), that the decision was correct, that the receipt is still redeemable, or that the receipt covers the action in front of you unless you compared `requestJson` and `inputHash` to it (section 3.3), or, for `jcs_v3`, the projection or the opened request.

For a `jcs_v3` receipt, the proof depends on what the verifier holds:

- **Anyone with the artifact** learns the decision, the decider, the policy version, the expiry, the time, the projected facts, for a decider who stepped up the signed evidence of that step-up, and that the issuer committed to exactly one request. It learns nothing else about that request, nor the summary, and it cannot check that the projection was built from the request. To decide whether the receipt covers an action, it compares the projected commit SHA, environment, capability, tool and operation.
- **The holder of the request and its salt** (section 6.7, step 3) also proves that the committed request is exactly that text, that the summary is the one committed with it, which workspace, idempotency key and input hash the issuer bound the receipt to (and that they are the stated ones, when it holds them), and that the projection was built from it by the published rule. For a `deploy_gate/v2` receipt on a private repository, that includes the matched rule the projection withholds.

### 6.5 Denials

A `DENIED` receipt verifies with the same procedure. Authenticity and outcome are separate axes: the issuer's public surfaces render a signed denial as an **authentic signature with a DENIED decision**, never as an authorization and never as a failure to verify. Verifiers SHOULD keep the same separation.

### 6.6 Online surfaces

`https://app.permissionprotocol.com/r/<id>` runs the issuer's full verification on every view and withholds a receipt whose bytes do not match its signature. `GET /api/v1/public/receipts/<id>` returns public fields with a `verification` block (`verified`, `signature_intact`, `signature_status`, `state`). `POST /api/v1/receipts/verify` is the tenant-authenticated endpoint CI gates use; it adds scope matching and atomic one-time redemption on top of the cryptographic check.

### 6.7 Verifying a `jcs_v3` receipt

A verifier runs these checks after the signature verifies and the canonicalization is `jcs_v3` (section 6.2, steps 5 and 6), in order, and reports the first failure. A failure in any of them is never reported as verified. A third-party verifier never reports it as tampering either, because the signature is intact (for the issuer's own check, see the end of this section).

**First, the payload is a `jcs_v3` payload. Every verifier MUST check it.** In order:

1. `receiptVersion` is the integer `3`. Otherwise: **malformed**.
2. `requestCommitment` is a string: `sha256:` followed by 64 lowercase hex characters (3.5). Otherwise: **request commitment malformed**.
3. `publicProjectionJson` is a string holding JSON text of an object whose top-level `projection` is a string. Otherwise: **malformed**.

No issuer's mint produces anything else under any tag, so such a receipt is malformed, never one a newer verifier could read. A malformed commitment is not **request commitment unavailable**: that code means only that the request text or the salt needed to open a well-formed commitment is missing (step 3).

**Step 1, the projection check. Every verifier MUST run it.** A third party cannot rebuild the projection without the request, but it can check that the signed projection is a possible output of the build rule for the tag it names. That check catches an issuer defect that would publish a field its tag does not allow.

1. If the top-level `projection` of `publicProjectionJson` is not a tag the verifier knows: **projection unsupported**. Fail closed; the receipt is unverifiable by that verifier, and may verify under a newer one.
2. Require `publicProjectionJson` to equal the canonical serialization of the parsed object (recursively sorted keys, no whitespace).
3. Walk every member of the object except `projection`. Each key MUST lie on a path of the tag's allowlist (3.7), with `[]` positions holding arrays and every other intermediate position holding objects.
4. At each listed leaf, the value MUST satisfy its slot. An **identifier** is a string matching `^[A-Za-z0-9._:/-]{1,128}$`. A **one of** slot holds one of its listed strings. A **value** slot holds a scalar or an array of scalars.
5. A † or ‡ path MUST NOT appear unless the projection's own `scope.visibility` is `"public"`. The build rule copies `scope.visibility` exactly when it is `public` or `private`, so this is equivalent to the rule applied to the request. `tools/public-projection.mjs` reports the first such path as `<path> is repository identity and scope.visibility is not "public"` for †, and `<path> is policy rule identity and scope.visibility is not "public"` for ‡.
6. A container MUST NOT be empty, except an array element `{}`. An array at a `[]` position MUST be non-empty, hold only objects, and have at least one non-empty element.

Any failure in items 2 to 6 is **projection not allowed**. It is a policy failure: the issuer signed something its own tag forbids, and the receipt MUST NOT be presented as verified.

**Step 2, the decider proof check. Every verifier MUST run it.** It needs only the signed payload.

1. If `deciderAuthMethod` is `session_stepup_webauthn` or `session_reauth`, `deciderProof` MUST be present. If it is any other value or absent, `deciderProof` MUST be absent. Otherwise: **decider proof mismatch**.
2. `deciderProof` MUST be an object in one of the two shapes of section 3.8: every rule there holds, including the re-authentication age, and it carries no key outside its shape. Otherwise: **decider proof invalid**.
3. Its `method` MUST be the one the auth method requires: `webauthn` for `session_stepup_webauthn`, `reauth` for `session_reauth`. Otherwise: **decider proof mismatch**.

Item 1 comes first, so a proof signed for an auth method that proves no step-up is a mismatch whatever it holds. Either failure is a policy failure: the issuer signed a decider proof its own format forbids, and the receipt MUST NOT be presented as verified. The shape check compares the proof's canonical text with the canonical text of the keys its shape allows, and treats a key named `__proto__` like any other key (it is outside every shape).

**Step 3, opening the commitment. A verifier MAY run it when it holds the request text and its salt.** Asked to open it without the request text or without the salt (for example, the issuer verifying a receipt whose salt it no longer holds): **request commitment unavailable**. When it also holds the summary the issuer states for the receipt (the owner field `summary`, 3.5), the opening checks that summary too. A stated summary is a string, or `null` for "none". When it holds any of the `companyId`, `idemKey` and `inputHash` the issuer states for the receipt (the owner fields `company_id`, `idem_key` and `input_hash`), the opening checks each one it holds.

1. Compute `"sha256:" + hex(SHA-256(salt || UTF-8(request text)))` over the request text exactly as given. If the result is not the signed `requestCommitment`, or the salt is not 32 bytes: **request commitment mismatch**.
2. Parse the request text. If it carries `receiptSummary` and that value is not a string, or the verifier holds a stated summary that is not the committed one: **committed summary mismatch**. A stated string holds exactly when `receiptSummary` is that same string; a stated `null` holds exactly when the request carries no `receiptSummary`.
3. If the request does not carry `receiptBinding` exactly as the mint writes it (3.5: an object with exactly the keys `companyId`, `idemKey` and `inputHash`, each a string or `null`), or the verifier holds a stated value for one of them that is not the committed one: **receipt binding mismatch**. A stated value holds exactly when it equals the committed value; a stated `null` holds exactly when the committed value is `null`. A missing or malformed binding fails whether or not any value is stated: the record cannot be the one the issuer committed.
4. Rebuild the projection from the request text under the tag that the signed projection names (3.6). If the result is not byte-equal to the signed `publicProjectionJson`: **public projection mismatch**.

A third-party verifier reports a step 3 failure as **commitment not opened**: the signature is intact, and the request, salt, summary or binding values it was given are not the ones committed to. The issuer is in a different position when it opens the commitment against its own stored request, salt, summary, `companyId`, `idemKey` and `inputHash`. A mismatch there means its stored record changed outside the signature after signing. The issuer reports the receipt as not intact, in those words (the stored record no longer matches what was signed), never as a forged or tampered signature, and treats it as it would a v2 receipt whose stored fields no longer match their signed bytes. That includes a stored summary, workspace, idempotency key or input hash that is no longer the committed one: `jcs_v2` signed those fields, and under `jcs_v3` the commitment binds them instead.

When step 3 passes, the request text is the one the issuer committed to, the summary and the binding are the ones committed with it, and the public projection was built from it by the published rule. A verifier without the request and salt reports the commitment as not opened, and draws no conclusion about the request beyond the projection, about the summary, or about which workspace the receipt belongs to. The issuer runs steps 2 and 3 on every verification it performs, and never redeems a receipt that fails either. It opens the commitment (step 3) before it resolves a key. It checks the decider proof (step 2) after the signature verifies, so it reports an issuer policy failure only on bytes whose signature is genuine; a payload with a bad signature is reported as a signature failure. A projection that passes step 3 also passes step 1. Because the issuer opens the commitment before it checks the decider proof, a receipt that fails both steps can be reported with a different first failure by the issuer and by a third party. Both report a failure.

**Reporting a withheld rule.** A projection whose tag marks ‡ paths (`deploy_gate/v2`) and whose `scope.visibility` is not `"public"` carries no matched rule. A verifier that reports the rule reports it as withheld. It MUST NOT report `policyVersion` in its place: the policy version names the policy that governed, not the rule that matched. Once the commitment is opened (step 3), it MAY report the rule the committed request records: the decision's `ruleId@ruleVersion`, else the override's, else the denial's `ruleId`. `tools/verify.mjs` and the issuer's npm verifier print `withheld (private repository): the signed projection carries no policy rule id or version; opening the request commitment shows it` (with `visibility not recorded, so treated as private` when the projection records none), and after an opening end it with `; the opened request commitment records <rule>` instead. A `deploy_gate/v1` projection carries the rule its request records, whatever the visibility, and a verifier reports it from there.

**One meaning per code.** Every surface that verifies a `jcs_v3` receipt gives each code below the same meaning, whatever its own exit codes or wording:

| Code | Class | `tools/verify.mjs` exit |
|---|---|---|
| `MALFORMED`, `REQUEST_COMMITMENT_MALFORMED` | malformed: the signed bytes are not a well-formed receipt (for the latter, the signed `requestCommitment` is missing or not `sha256:<64 lowercase hex>`) | 3 |
| `CANONICALIZATION_UNSUPPORTED`, `PROJECTION_UNSUPPORTED` | unverifiable here, not tampered: a newer verifier may read it | 8 |
| `REQUEST_COMMITMENT_UNAVAILABLE` | unverifiable, not tampered: an opening was required, and the request text or the salt it needs is missing | 8 |
| `PROJECTION_NOT_ALLOWED`, `DECIDER_PROOF_MISMATCH`, `DECIDER_PROOF_INVALID` | policy failure: the signature is valid, and the issuer signed what its own format forbids | 9 |
| `REQUEST_COMMITMENT_MISMATCH`, `COMMITTED_SUMMARY_MISMATCH`, `RECEIPT_BINDING_MISMATCH`, `PUBLIC_PROJECTION_MISMATCH` | the private record (request, salt, summary, binding values) does not match what was signed: for a third party, the commitment is not opened; for the issuer, its stored record changed outside the signature. Never a forged signature | 10 |

`tools/verify.mjs` runs the checks before step 3 on every `jcs_v3` receipt, and runs step 3 when given `--request <file> --salt <64 hex>`; `--summary <file>` adds a stated summary, read as exact text less one trailing line ending (`\n` or `\r\n`, so a file written by `echo` or an editor states the summary without it; a summary that itself ends in a line ending needs one more in the file), and `--binding <file>` adds stated binding values, a JSON object holding any of `companyId`, `idemKey` and `inputHash`. Its exit codes are those of the table.

## 7. Decision and decider semantics

### 7.1 Decisions

`status` is `APPROVED` or `DENIED`. Nothing else is signed. `APPROVED` means the action was authorized under the stated policy version, by the stated decider, at the stated time, for the snapshot in `requestJson` (under `jcs_v3`, the committed request). `DENIED` means it was refused, by policy or by a human, and is signed with the same ceremony. Pending holds (`REQUIRES_APPROVAL`, `REQUIRES_FOUNDER_VETO`), `EXPIRED`, and `ERROR` are lifecycle states of the issuer's row; they carry no signature and are not receipts under this document. (`ALLOW` and `DENY` are the raw vocabulary of the older ledger lane, which is not routed today; verifiers MAY accept them as aliases but will not encounter them from the hosted service.)

### 7.2 Decider identifiers

Every form of `deciderId` the hosted service writes, with the lane and the other attribution fields it comes with:

| `deciderId` | Lane | `deciderAuthMethod` | `attributionConfidence` | `resolutionType` | Meaning |
|---|---|---|---|---|---|
| `user:<userId>` | deploy gate (session or CLI) | `session`, `session_stepup_webauthn` or `session_reauth` | `credentialed` | `allow_once` | A human, authenticated by session, resolved to an owner or admin of the tenant. `deciderDisplay` is the GitHub login. **Names a human.** |
| `api_key:<keyId>` | deploy gate (API key) | `api_key` | `credentialed` | `allow_once` | A machine credential holding the approval scope. Not a human. |
| `demo:<actorId>` | public demo | `anonymous_demo` | `unattributed` | `allow_once` or `deny` | The anonymous public demo signer. Always `scope: demo`, always the demo key. |
| `system/pp-engine` | deploy gate, webhook auto-clearance | absent (null) | `credentialed` | `allow_once` | The policy engine cleared the change on push under `deploy-gate-v1`. No human approved. |
| `system/pp-permission-router` | execute lane | `policy` | `credentialed` | absent | The router's policy evaluation cleared or denied the action, including kill-switch denials. No human approved. |
| `system/pp-policy-engine` | ledger lane (not routed today) | `policy` | `credentialed` | absent | The PPv1 engine. Listed for completeness. |
| `user:<userId>` | execute lane, signed at the decision | `session`, `session_stepup_webauthn` or `session_reauth` | `credentialed` | `allow_once` | A human approved the hold, and the authorization was signed in that same request, before the action ran, with the identity captured from the live session (section 9.1). **Names a human.** |
| `user:<userId>` | execute lane | `session`, `session_stepup_webauthn` or `session_reauth` | `heuristic` | `allow_once` or `deny` | A human resolved the hold in the approvals surface, bound as the individual since 2026-09-08. `deciderDisplay` is the GitHub handle. **Names a human.** `heuristic`, not `credentialed`, because the identity is read from the approval record at signing time rather than captured at the moment of signature: see 7.3 and 7.4. |
| `role/human-approver` | execute lane | `session` | `heuristic` | `allow_once` or `deny` | A human resolved the hold. Every execute-lane human decision before 2026-09-08 carries this, and so does one after that date whose approval record names no resolvable individual: see 7.4. |
| `role/founder` | execute lane | `session` | `heuristic` | `allow_once` or `deny` | As above, for a hold flagged as a founder veto (`FOUNDER_VETO_REQUESTED` in `reasonCodes`). Since 2026-09-08 such a decision binds `user:<userId>` instead and the founder marker stays in the signed `reasonCodes`. |
| `role/api-key-approver` | execute lane | `api_key` | `heuristic` | `allow_once` or `deny` | The hold was resolved with an API key. Not a human. |

**Dated note, 2026-09-08.** Execute-lane human decisions now bind the individual (`user:<userId>`, GitHub handle in `deciderDisplay`, `attributionConfidence: heuristic`). Shipped in `permission-protocol/app` as ADR 0002, `docs/adr/0002-decider-attribution-execute-lane.md`. Receipts signed before that date bind a role class and are never re-signed, so a verifier will meet both forms and must accept both. The API-key lane on the execute path still binds `role/api-key-approver`, because the approvals routes do not learn which key approved. Nothing about the signed field set, the canonicalization, or the vectors changes: `deciderId` was always a string and the schema always accepted this form.

To an assessor, every `system/*` decider is a signed statement that **no human approved this**: the action cleared or was refused deterministically under the recorded `policyVersion`, which is the accountable authority. An auto-clearance can therefore never be mistaken for a human signature, nor a human decision for an automatic one.

### 7.3 Attribution confidence

- `credentialed`: the decider authenticated to the issuer at decision time (session, API key) or is a named policy version. The proof strength of a `session` decider equals the issuer's login: a GitHub OAuth session resolved to tenant membership. Step-up authentication at signing shipped as two `deciderAuthMethod` values, `session_stepup_webauthn` and `session_reauth` (observed on production receipts by 2026-10-03), not as a new field. A `jcs_v3` receipt also signs the evidence of the step-up, `deciderProof` (3.8); a `jcs_v2` receipt signs the label alone. Execute-lane human approvals signed at the decision are `credentialed` (section 9.1).
- `heuristic`: the identity was joined from the approval record at signing time rather than captured at the signature. This is an execute-lane decision signed after the decision request: every execute-lane human decision before authorization-first signing (section 9.1), and since then one whose signing at the decision was deferred (a freeze or pause on the action, a signer outage) and happened at redemption instead (7.4).
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

`prev` is **reserved** for `jcs_v4` and is not emitted today. `jcs_v3` (sections 3.4 to 3.8) carries the receipt-privacy change and the signed decider proof, and no chain field: no `jcs_v3` receipt carries `prev` or any digest of another receipt's bytes. `prev` was evaluated for this document and deferred, because adding it touches more than this repository can carry:

- A new signed field means a new canonicalization version and a new column on the issuer's receipt row (a schema migration), plus a signer change to read the tenant's previous head under the same transaction that mints the new receipt, plus a decision on stream granularity and checkpoint venue that is an open question for the founder.
- Every verifier, this repository's vectors, and the issuer's own re-canonicalization on verify would change with it.

The issuer's `idemKey` uniqueness per tenant and its append-only row model are not a substitute: they are issuer-side properties a verifier cannot check. Tracked as an issue in this repository; see `VERSIONING.md` for how the field will be introduced.

## 9. Execution attestations (`attest_v1`)

A receipt proves authorization. On the execute lane the issuer also records what happened when an `APPROVED` authorization was acted on, as a separate signed object: the **execution attestation**. It references the receipt by id. It never changes the receipt, and the receipt never changes because of it.

### 9.1 When the issuer emits one

- **Authorization comes first.** The issuer signs the `APPROVED` receipt before the action runs: for a policy clearance, when policy allows; for a human approval, in the request in which the human approves (the identity captured from the live session, `credentialed`), or, if that could not happen then, when the agent redeems the approval and before anything runs. An authorization that cannot be signed is not acted on.
- **Then exactly one execution, then one attestation.** The issuer acts on the authorization once and attests the outcome. At most one attestation exists per receipt.
- **Outcomes.** `succeeded`: the action's adapter returned; `outputHash` commits to what it returned. `failed`: the adapter reported failure. `unknown`: the issuer cannot know whether the action took effect: the adapter reported an indeterminate result (with a start time), or the process stopped after claiming the execution and before recording its outcome, in which case the issuer records `unknown` with no times and no output after a 15-minute stale window. The issuer never re-runs an action to resolve `unknown` and never upgrades it.
- **No attestation:** for deploy-gate receipts (the merge or deploy happens elsewhere, gated on redeeming the receipt); for authorize-only actions, where another system performs the action after it sees `APPROVED` (the issuer executed nothing, so it attests nothing); for an authorization not acted on yet; and for receipts minted before the issuer began emitting attestations (2026-10, ADR 0003 in `permission-protocol/app`). Absence is not evidence of either outcome.
- **Unsigned outcome.** If the issuer cannot sign an attestation after bounded retries, it records the outcome unsigned and flagged (`signing_failed`). Such a record proves nothing (section 9.5); the receipt's authorization signature is unaffected.

### 9.2 Signed fields

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `approvalReceiptId` | string | always | The `id` of the `APPROVED` receipt this attests. |
| `outcome` | string | always | `succeeded`, `failed`, or `unknown`. |
| `toolCallId` | string | optional | The adapter's own identifier for the call, when it returned one. |
| `outputHash` | string | optional | `sha256:` plus lowercase hex SHA-256 of the canonical JSON (recursively sorted keys, no whitespace, UTF-8) of what the adapter returned. Unsalted: it confirms a guessed output, so the issuer does not publish attestation bytes on its public surface (9.4). |
| `startedAt` | string | optional | ISO 8601 UTC with milliseconds. When the issuer started the action. |
| `finishedAt` | string | optional | When the adapter returned or failed. |
| `attestationVersion` | integer | always | `1`. |
| `canonicalization` | string | always | `attest_v1`. |
| `signatureAlg` | string | always | `ed25519`. |
| `signatureKeyId` | string | always | The same issuer key set as receipts. |
| `createdAt` | string | always | When the issuer recorded the outcome. |

Consistency rules a verifier checks after the signature: `startedAt` and `finishedAt`, when present, are strings holding an ISO 8601 instant exactly as the table states it (`YYYY-MM-DDTHH:mm:ss.sssZ`, a real date), and `outputHash`, when present, is a string of the stated form; nothing is coerced. `succeeded` and `failed` carry `startedAt` and `finishedAt`, with `finishedAt` not before `startedAt`; `unknown` carries neither `finishedAt` nor `outputHash` (if either were known, the outcome would be too). The tenant is not signed: receipt ids are unique, and the receipt's own signature binds what was authorized. `schema/attestation-v1.json` encodes the table.

### 9.3 Canonicalization and signature

`attest_v1` applies the byte rules of section 4 to the field list above: listed fields only, `null` and absent skipped, keys sorted recursively, dates as ISO 8601 with milliseconds, `JSON.stringify` without whitespace, UTF-8. The signature is Ed25519 over the SHA-256 digest of those bytes, with a key from the receipts' key set. `attest_v1` is frozen under the same rule as a receipt canonicalization (`VERSIONING.md`); it is the attestation's own identifier and never a `jcs_v*` value.

### 9.4 The attestation artifact

Served as `attestation_artifact` next to `artifact` for an execute-lane receipt (`null` when it has none; absent for deploy-gate receipts):

```json
{
  "attestation_artifact": {
    "approval_receipt_id": "cmvec02policyclear00000000001",
    "outcome": "succeeded",
    "attestation_version": 1,
    "canonicalization": "attest_v1",
    "key_id": "pp-test-2026-q2",
    "alg": "ed25519",
    "signed_payload_hash": "<64 hex>",
    "signature_b64": "<64-byte Ed25519 signature, base64>",
    "payload_bytes_b64": "<the exact attest_v1 bytes, base64>",
    "issued_at": "2026-09-01T14:05:00.512Z"
  }
}
```

- The owning tenant's `GET /api/v1/receipts/<receipt_id>/artifact` carries `payload_bytes_b64`.
- The public `/r/<receipt_id>.json` carries `payload_withheld: true` instead (digest and signature only), for the reason in 9.2. Its `outcome` is then an unsigned statement of the issuer, given only when the issuer's own full verification of the record passed, and `null` otherwise. A third party can confirm that the issuer signed the digest, not what it contains; the workspace verifies the outcome offline from its own artifact.
- An unsigned record is `{ "approval_receipt_id", "outcome", "attestation_version": 1, "signed": false, "signing_failed": true, "issued_at" }`, with no signature fields.

### 9.5 Verify procedure

1. Verify the receipt the attestation names (section 6.2). Require its `id` to equal `approval_receipt_id` and its `status` to be `APPROVED`. Otherwise: **receipt mismatch** or **receipt not approved**.
2. `signed: false`: report **unsigned outcome**, not verified and not tampered. `payload_withheld: true`: report **withheld**, not verified and not tampered (whatever `outcome` says).
3. Require `approval_receipt_id`, `key_id`, `alg` (`ed25519`), `signed_payload_hash`, `signature_b64`, `payload_bytes_b64`. Otherwise **malformed**.
4. SHA-256 of the decoded bytes must equal `signed_payload_hash` (**payload hash mismatch**); the parsed object's `signatureKeyId` must equal `key_id` (**malformed**); re-canonicalizing it under `attest_v1` must reproduce the bytes (**canonical mismatch**).
5. Resolve the key and verify Ed25519 over the digest, exactly as 6.2 steps 4 and 5.
6. Require the signed `approvalReceiptId` to equal the envelope's, and apply the 9.2 consistency rules (a failure here is a policy failure, not tampering).

`tools/verify.mjs <attestation.json> <keys.json> --receipt <receipt.json>` implements this.

### 9.6 What an attestation proves

That the issuer recorded this outcome for this authorization at `createdAt`, under its key. `succeeded` and `failed` attest what the action's adapter returned to the issuer, not the state of the target system; `unknown` says the issuer does not know. An authorization with no attestation is "authorized, execution not confirmed by the issuer". The receipt alone still proves only the authorization.

## 10. Lifecycle around the receipt

- **Expiry.** `expiresAt` bounds redemption of an approval by a CI gate or an agent retry. It does not expire the evidence; an expired receipt still verifies.
- **Redemption.** The issuer's verify endpoint can redeem an approval atomically once. Redemption state is unsigned issuer metadata.
- **Idempotency.** A resubmitted execute-lane request with the same `idemKey` returns the existing receipt; a `DENIED` receipt is terminal for its key (kill-switch denials say so in `reasonCodes` with `KILL_SWITCH_DENIAL_TERMINAL`). A changed action under a reused key is refused with a fresh `DENIED` receipt (`APPROVAL_ARTIFACT_MISMATCH`). Under `jcs_v3`, `idemKey` and `inputHash` are not signed; they are committed under `receiptBinding` (3.5), and the issuer checks its stored values against them on every verification.
- **Re-approval.** An expired deploy-gate approval can be renewed for the unchanged scope; the renewal is a new receipt with its own id and `DEPLOY_GATE_REAPPROVED` in `reasonCodes`, signed by the renewing decider.
- **Revocation.** An unused deploy-gate approval (not redeemed, not merged) can be revoked. The revocation is a new `DENIED` receipt (`rcpt_rev_<uuid>`, `resolutionType` `deny`) whose request names the revoked receipt in `metadata.revokedReceiptId` and whose summary is the revoker's reason: signed under `jcs_v2`, committed under `jcs_v3`. The revoked receipt is not re-signed.

## 11. Security considerations

- **Replay.** A valid signature does not prove the receipt is for the action in front of you. Compare `requestJson` and `inputHash` to your own canonical input, and use `idemKey` or the issuer's redemption for one-time execution. For `jcs_v3`, a third party compares the projected commit SHA, environment, capability, tool and operation, and the holder of the request opens the commitment; one-time execution rests on the issuer's redemption.
- **Workspace and idempotency binding.** A `jcs_v3` receipt signs neither `companyId` nor `idemKey` nor `inputHash`, and one issuer key signs for every workspace, so the signature alone does not say which workspace a receipt belongs to. The committed `receiptBinding` does (3.5): the issuer opens it on every verification and reports a stored value that differs as receipt binding mismatch, and a holder of the request compares it with the stored values it was given. A third party without the request learns none of the three.
- **Commitment salt.** A `jcs_v3` salt is as sensitive as the request it opens. With the salt, a guessed request can be confirmed against the commitment. A disclosed salt opens only its own receipt, because every receipt has its own salt.
- **Projection allowlist.** The projection check (6.7, step 1) is how a third party detects an issuer that published a field its tag does not allow. Verifiers MUST run it and MUST fail closed on a tag they do not know.
- **Matched rule.** Under `deploy_gate/v2` a private repository's matched rule is committed, not published: neither the projection (3.7) nor `reasonCodes` (3.4) carries it, and a verifier never shows `policyVersion` as the rule (6.7). A `deploy_gate/v1` receipt publishes the rule its request records, whatever the visibility.
- **Committed summary.** A `jcs_v3` summary is not signed. A summary shown beside a `jcs_v3` receipt is unsigned issuer data unless the commitment was opened and the summary matched (6.7, step 3). Do not decide anything from it otherwise.
- **Decider proof.** A step-up label without its proof, a proof without a step-up label, or a proof outside its frozen shape is a policy failure that only the decider proof check (6.7, step 2) catches. Verifiers MUST run it. A valid proof shows what the issuer recorded about the step-up; the authenticator's own assertion is not in the receipt, and a verifier cannot re-check it.
- **Unsigned metadata.** Anything outside the signed set (section 3.1, or 3.4 for `jcs_v3`) is mutable. Do not decide anything from it.
- **Key compromise.** The issuer holds one production signing key per deployment in environment configuration; its compromise would forge receipts for every tenant until revocation. Verifiers MUST honor `revoked` and SHOULD re-fetch the key set periodically.
- **Canonicalization drift.** Any change to the bytes breaks every existing signature. Implementers MUST test against `test-vectors/` and the live vector; step 6 of the verify procedure exists to catch drift on the issuer's side too.
- **Time.** Expiry comparisons depend on the verifier's clock. Treat expiry as information about redemption, not as a signature property.
- **Demo scope.** Never accept `scope: demo` or key id `pp-demo-k1` as production evidence, whatever the rest of the receipt says.

## 12. Conformance

`test-vectors/` holds:

| File | What it is | Expected result |
|---|---|---|
| `approve-human-deploy-gate.json` | `APPROVED` by a session-authenticated human on the deploy-gate lane, `user:<id>` | verifies |
| `approve-policy-execute-lane.json` | `APPROVED` by the policy engine on the execute lane, read-only tier | verifies |
| `deny-kill-switch-execute-lane.json` | `DENIED` under a global freeze before policy evaluation, terminal for its key | verifies, decision `DENIED` |
| `tampered-approve-human-deploy-gate.json` | vector 1 with `summary` edited after signing and the hash recomputed | fails at the signature |
| `approve-human-execute-lane-refund.json`, `approve-human-execute-lane-create-pr.json` | `APPROVED` by a named human on the execute lane, signed at the decision before the action ran (`credentialed`, 15-minute window) | verify |
| `attestations/attest-succeeded-policy-execute-lane.json`, `attest-failed-human-execute-lane-create-pr.json`, `attest-unknown-human-execute-lane-refund.json` | one execution attestation per outcome, each naming its receipt vector (`receipt_vector`) | verify with `--receipt` (section 9.5) |
| `attestations/tampered-attest-failed-human-execute-lane-create-pr.json` | the failed attestation rewritten as succeeded after signing, hash recomputed | fails at the signature |
| `v3/approve-human-deploy-gate-private-repo.json` | `jcs_v3`, deploy-gate approval by a named human after a passkey step-up, on a private repository: the `deploy_gate/v1` projection carries no repository identity; a `webauthn` decider proof | verifies |
| `v3/approve-human-deploy-gate-public-repo.json` | `jcs_v3`, the second approval under a two-approver rule on a public repository, after a fresh sign-in: the projection carries the † paths, and the recorded decisions as display name and time only (no user id, no auth method); a `reauth` decider proof | verifies |
| `v3/approve-human-execute-lane-refund.json` | `jcs_v3`, execute-lane human approval over a plain session: the `execute/v1` projection carries the intent and action names, never the parameters; no decider proof | verifies |
| `v3/revoke-human-deploy-gate.json` | `jcs_v3`, the private-repository approval revoked: `revocation/v1`, `DENIED`; the reason is the committed summary; no visibility recorded, so no repository identity | verifies, decision `DENIED` |
| `v3/tampered-approve-human-deploy-gate-private-repo.json` | the projection's commit SHA edited after signing, hash recomputed | fails at the signature |
| `v3/outside-allowlist-approve-human-execute-lane-refund.json` | validly signed with the test key over a projection that also carries `action.parameters` | signature verifies; fails the projection check (projection not allowed) |
| `v3/decider-proof-mismatch-approve-human-execute-lane-refund.json` | validly signed with the test key over a `webauthn` decider proof beside `deciderAuthMethod` `session` | signature verifies; fails the decider proof check (decider proof mismatch) |
| `v3/non-canonical-proof-approve-human-execute-lane-refund.json` | validly signed with the test key over a `webauthn` decider proof that also carries the authenticator's `counter` | signature verifies; fails the decider proof check (decider proof invalid) |
| `v3/no-binding-approve-human-execute-lane-refund.json` | validly signed with the test key over a commitment to a request that carries the summary but no `receiptBinding` | verifies for a third party; its opening fails (receipt binding mismatch) |
| `v3/approve-human-deploy-gate-v2-private-repo.json` | `jcs_v3` under `deploy_gate/v2`: a customer protected-path rule's hold on a private repository, approved by a named human after a passkey step-up. The projection carries neither repository identity (†) nor the matched rule's id and version (‡) | verifies; the rule is reported as withheld, and its opening names the committed rule |
| `v3/approve-human-deploy-gate-v2-public-repo.json` | `jcs_v3` under `deploy_gate/v2`: a built-in hold on a public repository, approved over a plain session. The projection carries the † and ‡ paths, as `deploy_gate/v1` would | verifies; the rule is `hold.protected_path@outcome-router-v1` |
| `v3/deny-policy-deploy-gate-v2-private-repo.json` | `jcs_v3` under `deploy_gate/v2`: the policy engine's denial on a private repository. No rule in the projection, and `reasonCodes` is `["DEPLOY_GATE_DENIED"]`, without the rule id | verifies, decision `DENIED`; the rule is reported as withheld, never as the signed `policyVersion` |
| `v3/published-rule-approve-human-deploy-gate-v2-private-repo.json` | validly signed with the test key over the private `deploy_gate/v2` approval's projection with `policy.decision.ruleId` and `.ruleVersion` put back | signature verifies; fails the projection check (projection not allowed: `policy.decision.ruleId is policy rule identity and scope.visibility is not "public"`) |
| `v3/openings/openings.json` | commitment openings: each committed request as exact text in `v3/openings/`, a salt, the summary and binding values stated beside it, and the expected result of section 6.7 step 3 | eight open, two of them stating their binding values and one stating no summary; another receipt's salt, a reformatted request and a changed request give request commitment mismatch; a summary edited after signing and a summary stated as none give committed summary mismatch; another workspace's `companyId` stated, and a request without `receiptBinding`, give receipt binding mismatch; the outside-allowlist and published-rule vectors give public projection mismatch |
| `conformance/expected-canonical-bytes.txt` | after the five v1 fixture digests, the SHA-256 of the canonical bytes of every `v3/` vector | an implementation's `jcs_v3` canonicalization of each vector's `receipt` reproduces its digest |
| `live-deploy-gate-approve.json` | a real production receipt captured from the public artifact endpoint on 2026-09-08 | verifies against `live-keys.json` |
| `keys.json`, `live-keys.json` | the key sets, in the published shape | |

The three generated vectors are produced by `tools/generate-vectors.mjs` from fixed inputs with the repository's test key; CI regenerates them and fails on drift. Their bytes were checked byte for byte against the issuer's own canonicalization code. An implementation claims conformance to this document when it reproduces every expected result above, passes `node --test "test/*.test.mjs"`, and validates each verified payload against `schema/receipt-v2.json` (`jcs_v2` receipts), `schema/receipt-v3.json` (`jcs_v3` receipts) or `schema/attestation-v1.json` (attestations).

The `jcs_v3` vectors use the same key, with fixed published salts in place of the issuer's random ones. The two `v3/` deploy-gate approvals without `v2` in their names are frozen history under `deploy_gate/v1`: the generator names their tag, so they keep their bytes now that the lane signs `deploy_gate/v2`.

**Regenerated 2026-10-06; issued since 2026-10-08.** On 2026-10-06 the `jcs_v3` vectors were regenerated: every committed request now carries `receiptBinding` (3.5), `deploy_gate/v1` no longer projects `recordedDecisions[].authMethod` (3.7), and the revocation vector records no visibility and signs the revoker's internal user id as its route does. The issuer commits `receiptBinding` since `permission-protocol/app#627` and has signed `jcs_v3` in production since 2026-10-08. On 2026-10-08 `tools/verify.mjs` at this revision verified, against the issuer's published key set, three production `jcs_v3` receipts: a passkey-stepped-up human approval (`rcpt_dg_cmuzqtq9l006o127zrquwuo6n`), a second human approval (`rcpt_dg_cmuzppxga003l127zj147lef0`) and a policy clearance (`rcpt_dg_cmuzru53s000beppuo4o36bop_clearance`), each a private repository's `deploy_gate/v1` projection within its allowlist; a production `jcs_v2` receipt verified unchanged. A byte-for-byte comparison of these vectors against the issuer's signer is repeated the way described next. To repeat it, sign the mint inputs that `node tools/generate-vectors.mjs --inputs <file>` writes (each request before the mint adds the binding and the summary, the summary, the binding, the stored step-up evidence and the salt) with the issuer's `signing/` modules, composed as its signer composes them, and the same key; then compare every committed request, commitment, projection, decider proof, canonical byte string, digest and signature, and run the issuer's verification over every case in `v3/openings/openings.json`.

The vectors as they stood before that change (receipt-spec `79d2dfa`, without `receiptBinding`) were checked on 2026-10-06 against the issuer's `jcs_v3` signing code at `permission-protocol/app` commit `6e611d95`: its `signing/` modules `canonicalize.ts`, `public-projection.ts`, `request-commitment.ts`, `decider-proof.ts` and `receipt-v3.ts`, composed exactly as its signer composes them, a composition that first reproduced the signer's own golden `jcs_v3` vectors. Given the same mint inputs and key:

- It produced the same committed requests, commitments, projections, decider proofs, canonical bytes, digests and signatures for every valid `jcs_v3` vector.
- Its verification agreed with every case in `v3/openings/openings.json`, and with the expected result of both decider-proof vectors. Every `v3/` vector re-canonicalized under its field list.
- Its decider proof check and its committed-summary check agreed with `tools/decider-proof.mjs` and `tools/verify.mjs` on 12,696 and 180 generated cases.
- Its signed field list and projection allowlists equaled this repository's at the time.

The issuer's projection builder was unchanged from commit `c655e8d5`, where it agreed byte for byte with `tools/public-projection.mjs` on 3,536 requests under all three tags: hand-written edge cases, the vector requests, and seeded random requests shaped along the allowlist paths. Every projection it built passed the projection check of section 6.7. The issuer's golden `jcs_v3` vectors at that commit (`tests/signing/receipt-canonicalization-golden.test.ts`: commitment `sha256:8177915c995f5702e172d3ae27510f128aaa6e1f79c4c39e6188ff8bfa69eb85`, payload digests `28d71600…`, `326c2927…` and `e6ad3101…` for a session, a passkey and a re-authentication decider) reproduced byte for byte with this repository's tools. With the golden row's binding committed, the same inputs give commitment `sha256:a57c62d3a69c2ea9142b14395ddb2d22750f1a349df738535bd434cb3b27ec11` and payload digests `40989bb0…`, `ff36bda2…` and `c6c72046…` (`test/v3-vectors.test.mjs`); the issuer's golden test has not yet been compared with them.

**`deploy_gate/v2` cross-check, 2026-10-08.** The `deploy_gate/v2` vectors were checked against the issuer's code at `permission-protocol/app#688` (head `7b33256a`: every verifier reads the tag) and at `permission-protocol/app#691` (the deploy-gate lane signs it; checked at its commit before it was opened):

- Its allowlists equal `tools/public-projection.mjs` path for path under all four tags, with the same slots, † and ‡ marks.
- Its `buildPublicProjection` gave the signed projection of every valid `v3/` vector from its committed request, byte for byte, and its projection check agreed with `tools/public-projection.mjs` on every `v3/` vector, the published-rule vector's message included.
- Its mint modules (`buildReceiptV3RequestBinding`, `buildReceiptV3DeciderProof`, `canonicalizeReceiptForVersion`), composed as its signer composes them, signed the mint inputs of the three valid `deploy_gate/v2` vectors with the test key to the same committed requests, commitments, projections, decider proofs, canonical bytes, digests and signatures. The same run reproduced the `execute/v1` and `revocation/v1` vectors, `receiptBinding` included, and the two `deploy_gate/v1` vectors with the projection built under their own tag.
- Its `ruleReasonCodes` gave the denial vector's signed `["DEPLOY_GATE_DENIED"]`, and `["DEPLOY_GATE_DENIED","deny.deterministic_dangerous_diff"]` for the same request marked public.
- Its opening (`checkReceiptV3RequestBinding`) agreed with every `deploy_gate/v2` case in `v3/openings/openings.json`.
- Its npm verifier (0.4.2, from that commit) verified the three valid vectors, reported the rule of the two private ones as withheld and named the committed rule once `--request` and `--salt` opened them, and failed the published-rule vector with exit 9 (`PROJECTION_NOT_ALLOWED`).

## 13. Relationship to other documents

- `RECEIPT-FORMAT-V1.md`: frozen, with errata in 5.5.
- `VERIFY.md`: the nine-line verification and the online paths.
- `MAPPINGS.md`: which fields back which controls.
- `VERSIONING.md`: how this format changes.
- In `permission-protocol/app`: `docs/receipt-standard.md` (the SDK-facing receipt object and status mapping), `permission-protocol-sdk/spec/hashable-payload-v1.md` (`inputHash` on the execute lane), `src/lib/permission-protocol-v1/signing/canonicalize.ts` (the frozen field lists this document transcribes), `src/lib/permission-protocol-v1/signing/public-projection.ts` and `request-commitment.ts` (the `jcs_v3` projection allowlists, build rule and commitment), `decider-proof.ts` (the `deciderProof` shapes and consistency rule) and `receipt-v3.ts` (the committed summary and the issuer's opening of the commitment), `docs/trust/design-notes/F2-RECEIPT-V3-PUBLIC-PROJECTION.md` (why `jcs_v3` exists and what it leaves public), `src/lib/permission-router/execution-attestation.ts` (`attest_v1`), `docs/adr/0003-authorization-before-execution.md` (why authorization precedes execution and the outcome is separate).
