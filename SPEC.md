# Permission Protocol Receipt Format, as emitted

**Version markers covered:** `receiptVersion` `2`, `canonicalization` `jcs_v2`; and `receiptVersion` `3`, `canonicalization` `jcs_v3` (sections 3.4 to 3.7 and 6.7). **Status:** the `jcs_v2` text describes what the hosted service at `app.permissionprotocol.com` has issued since 2026-07-09, traced field by field to the code that writes it. `jcs_v3` is specified before it is issued: the issuer's implementation (`permission-protocol/app` commit `c655e8d5`) sits behind a switch that is off by default, its bytes were checked against `test-vectors/v3/`, and no `jcs_v3` receipt had been issued as of 2026-10-06. The issuer turns it on only once this text is published, and `VERSIONING.md` will record the date it does. **Date:** 2026-09-08; `jcs_v3` sections 2026-10-06. **License:** CC BY 4.0 for this text; Apache-2.0 for the schemas, vectors, and tools.

This document supersedes `RECEIPT-FORMAT-V1.md` as the description of the current format. The v1 document stays in this repository unchanged, because it is what `jcs_v1` receipts were published against; section 5.5 records where it disagreed with the product.

## 1. Purpose and scope

A receipt is a signed statement that one decision was made about one gated action: approved or denied, by whom, under which policy version, at what time, against which exact action snapshot. It is issued by the system that made or recorded the decision and verified by anyone holding the issuer's public key. It proves authorization. It does not prove that the action ran, that it succeeded, or that the decision was wise.

In scope: the signed payload (section 3; for `jcs_v3`, the request commitment and public projection that replace the request in the signed bytes, sections 3.4 to 3.7), how its bytes are built (section 4), how they are signed and how keys are found (section 5), the portable envelope and the verify procedure (section 6), and what the decision and decider fields mean (section 7).

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
- **Committed request** (`jcs_v3`): the issuer's private action snapshot, `requestJson`, bound into the signature through a salted commitment (section 3.5) instead of being carried in the signed bytes.
- **Public projection** (`jcs_v3`): the part of the committed request that the allowlist of the receipt's lane makes public, signed as `publicProjectionJson` (section 3.6). Its **projection tag** names the allowlist and its version: `deploy_gate/v1`, `execute/v1` or `revocation/v1` (section 3.7).
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
| `reasonCodes` | string | optional | A JSON array of strings, serialized as text. Order preserved. Examples: `["DEPLOY_GATE_APPROVED"]`, `["READONLY_OPERATION"]`, `["GLOBAL_FREEZE_ACTIVE","KILL_SWITCH_DENIAL_TERMINAL"]`, `["APPROVAL_DENIED","FOUNDER_VETO_REQUESTED"]`. |
| `summary` | string | optional | Human-readable summary of the decision context. |
| `deciderId` | string | always (v2) | Stable id of who decided. Section 7.2 lists every form in use. |
| `deciderDisplay` | string | always (v2) | Human-facing label: the GitHub login for a session signer, a fixed label for the policy engine, a role-class label on the execute lane. |
| `deciderAuthMethod` | string | optional (v2) | `session`, `session_stepup_webauthn`, `session_reauth`, `api_key`, `anonymous_demo`, or `policy`. The two step-up values name a human who gave fresh proof of presence at the moment of signing (a passkey assertion, or a recent re-authentication) on top of the session. Absent where the mint path recorded null: the deploy-gate webhook auto-clearance (`system/pp-engine`). |
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

Under `jcs_v3` (section 3.4) four more stored fields fall outside the signed set: `companyId`, `idemKey`, `requestJson` and `inputHash`. The signature still binds `requestJson`, through `requestCommitment`. The salt that opens that commitment (`requestCommitmentSalt`, 32 bytes) is stored beside the receipt, is never signed, and is never placed on a public surface.

### 3.3 `requestJson`

`requestJson` is the exact action the decider saw, serialized once by the issuer with recursively sorted keys and no whitespace, then stored and signed as a string. Signing the string rather than an embedded object is deliberate: the bytes cannot drift with a re-serialization.

Its contents are lane-specific and issuer-defined. Verifiers MUST treat `requestJson` as authenticated **text** and MAY parse it for display or scope checks. The two shapes today:

- Deploy gate: `{ action: { operation: "deploy", tool: "github-actions" }, context: { environment, reversibility: "REVERSIBLE" }, enrichmentSnapshot, intent: { category: "deployment", name: "deploy_gate_approval", summary }, metadata: { deployGateRequestId, ... demo markers when scope is demo }, policy: { decision, expiresAt }, scope: { artifact_digest, capability, commitSha, env, ref, repo, workflow } }`.
- Execute lane: the caller's full request as canonical JSON: `{ action: { operation, parameters, tool }, actor: { agentId, runId }, constraints?, context: { environment, reversibility, ... }, hashes: { inputHash }, intent: { category, name, summary }, tenantId }`.

A verifier checking that a receipt covers the action in front of it compares the fields it cares about (repository, commit, tool, parameters) against the parsed `requestJson`, and the digest of its own canonical input against `inputHash`.

Under `jcs_v3`, `requestJson` is not in the signed bytes. The issuer stores it as canonical text (sorted keys, no whitespace) and signs a commitment to it (3.5) and a projection of it (3.6).

### 3.4 The `jcs_v3` signed payload (`receiptVersion` 3)

A receipt link travels well beyond the workspace that owns it: pull-request comments and commit statuses, notifications, forwarded messages. The public artifact carries the signed bytes, so under `jcs_v2` those bytes publish the request itself: repository names, changed paths, model-written descriptions of a private change, an agent's parameters. `jcs_v3` signs a salted commitment to the request and an allowlisted projection of it instead. It is designed so that its signed bytes carry nothing the public receipt page does not show, while the signature still binds exactly one request.

The `jcs_v3` signed field set has 22 fields and is frozen:

`id`, `agentId`, `runId`, `requestCommitment`, `publicProjectionJson`, `status`, `riskTier`, `policyVersion`, `reasonCodes`, `summary`, `receiptVersion`, `canonicalization`, `signatureAlg`, `signatureKeyId`, `expiresAt`, `createdAt`, `deciderId`, `deciderDisplay`, `deciderAuthMethod`, `resolutionType`, `attributionConfidence`, `scope`.

Relative to `jcs_v2`:

| Change | Field | Type, presence | Why |
|---|---|---|---|
| removed | `companyId` | | The tenant id links one workspace's receipts across repositories. |
| removed | `idemKey` | | Deploy gate: embeds the unsalted scope hash. Execute lane: the caller's free-text idempotency key, or else the unsalted `inputHash`. |
| removed | `requestJson` | | The private request. Committed and projected instead. |
| removed | `inputHash` | | An unsalted hash over the request or its scope confirms a guessed repository, recipient or parameter. |
| added | `requestCommitment` | string, always | `sha256:` plus 64 lowercase hex: a salted commitment to the exact `requestJson` text (3.5). |
| added | `publicProjectionJson` | string, always | Canonical JSON text of the public projection of `requestJson`, naming its tag (3.6, 3.7). |

The other 20 fields keep the types and meanings of section 3.1, except that `receiptVersion` is the integer `3` and `canonicalization` is `jcs_v3`. Every `jcs_v3` receipt signs a decider: `deciderId`, `deciderDisplay`, `attributionConfidence` and `scope` are always present. `schema/receipt-v3.json` encodes this table with `additionalProperties: false`.

**Which receipts are `jcs_v3`.** Once the issuer turns `jcs_v3` on, every mint path with a projection tag signs it: the deploy-gate lane (human approve and deny, webhook clearance and policy denial, re-approval, carry-forward, denial repair, policy override, demo approve and deny, merged-PR deployment renewal), the execute lane, and revocations. The ledger lane, which is not routed today, has no tag and keeps signing `jcs_v2`. Receipts already signed under `jcs_v1` or `jcs_v2` keep their bytes and verify under their own rules forever; nothing is re-signed, rewritten or migrated (`VERSIONING.md`).

**`summary` stays signed and public.** It is the decision's stated reason, and it can carry text a decider typed: an approval or denial reason, an override justification, a revocation reason. Where the issuer writes the summary itself, `jcs_v3` mint paths sign fixed issuer text rather than a model-written description of the change. A deploy-gate webhook clearance, for example, signs `PP analyzed this change and cleared it under default policy`.

### 3.5 `requestCommitment`

```
requestCommitment = "sha256:" + lowercase_hex( SHA-256( salt || UTF-8(requestJson) ) )
```

- **`salt`** is 32 bytes from a cryptographically secure random generator, drawn fresh for each receipt and never reused. The fixed length makes the concatenation unambiguous. The issuer stores it beside the receipt; it is not signed and is never published on a public surface.
- **`requestJson`** is the exact stored request text, byte for byte. Under `jcs_v3` the issuer stores canonical text (3.3) and refuses to sign anything else. An opening hashes the text as given and never re-serializes it, so a pretty-printed copy of the same object does not open the commitment.
- **Binding** rests on the collision resistance of SHA-256: the signature commits the issuer to exactly one request text. **Hiding** rests on the salt: without it the commitment confirms nothing about a guessed request, which is the property `inputHash` lacked.
- **One salt per receipt**, not per workspace. Two receipts over the same request get unlinkable commitments, and the workspace can open one receipt for an auditor without opening any other.

The issuer opens the commitment on every verification it performs. The workspace that owns the receipt receives the request text and its salt through the issuer's authenticated surfaces, under two fields on each `jcs_v3` receipt they carry:

- **`request_json`**: the stored request text, byte for byte (a JSON string whose value is that text).
- **`request_commitment_salt_b64`**: the 32-byte salt, standard base64; `null` when the issuer no longer holds it, in which case the commitment cannot be opened.

These fields appear only on authenticated owner surfaces (the owner artifact, evidence packages, exports), never on the public artifact. On v1 and v2 receipts they are absent or `null`. Anyone the workspace gives one receipt's request and salt can open that receipt (section 6.7, step 2).

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
3. Paths marked **†** are repository identity. They are copied only when the same request's `scope.visibility` is exactly the string `"public"`; absent or any other value counts as private. The issuer records `scope.visibility` (`public` or `private`) at signing from what GitHub reported for the repository, and records none when it learned nothing.
4. Remove every object or array that the build created and that received nothing, recursively. Array elements are the exception: they stay as `{}` while any element of the same array received something. An array whose elements all received nothing is removed.
5. Add the top-level key `projection` with the tag as its value, sort keys recursively, and serialize without whitespace (`JSON.stringify` semantics). The result is `publicProjectionJson`.

`tools/public-projection.mjs` implements the rule; section 12 records its byte-for-byte check against the issuer's implementation.

**Tags are frozen.** A tag's allowlist is frozen once a receipt is signed with it, under the same rule as a canonicalization version. A new lane or a changed allowlist is a new tag, such as `deploy_gate/v2`, not a new canonicalization: the signed field set and the byte rules stay the same. A verifier that does not know a tag fails closed (section 6.7).

### 3.7 Projection allowlists

Each table is normative. It lists every path its tag may publish, in build order, with the slot kind from 3.6 step 2 (**value**, **identifier**, or **one of** the listed strings). † marks repository identity (3.6 step 3). A path that is not listed is never projected.

#### `deploy_gate/v1`

Signed by every deploy-gate mint path listed in 3.4: intents `deploy_gate_approval`, `deploy_gate_denial` and `deploy_gate_policy_override`, and the merged-PR deployment renewal.

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
| `policyAuthorization.recordedDecisions[].authMethod` | value |  |
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
| `deploymentRenewal.recordedDecisions[].authMethod` | value |  |
| `deploymentRenewal.recordedDecisions[].at` | value |  |

The commit SHA, the artifact digest, the policy commit and the rules hash are projected for every repository. They bind the receipt to exact content for anyone who can see the repository, and they reveal nothing to anyone who cannot. For a private repository, the projection does not carry the repository name, ref, workflow, branches, changed paths or pull-request number.

Never projected, so they stay behind the commitment:

- `enrichmentSnapshot`, all of it.
- `intent.summary`.
- From `policy.decision.matchedInputs`: `riskSignals`, `repoPolicy` (the customer's rule rationale and matched files), `approvalRequirements` (approver lists), `ruleEvaluations` and `findings`.
- `metadata.denial.reason` and `.deciderKind`. The signed `deciderId` already names who denied.
- `metadata.override.justification`, `.overriddenDecider`, `.overriddenDeciderKind` and `.deniedGeneration`.
- `policyAuthorization.requirements`, `.binding`, `.repo`, `.round`, `.policyRef` and `recordedDecisions[].userId`.
- `deploymentRenewal.reviewBinding`, an unsalted hash over guessable scope and branch facts, and `deploymentRenewal.recordedDecisions[].userId`.
- Every key that is not listed.

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

Signed by revocations. The scope is copied from the revoked receipt's request, so the † rule follows the visibility recorded there. A revoked `jcs_v2` receipt recorded no visibility, so its revocation projects no repository identity.

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

Never projected: `metadata.reason` (free text; it is also the signed `summary`) and `intent.summary`.

## 4. Canonicalization (`jcs_v2`, `jcs_v3`)

The signed bytes are built as follows. This is exactly the issuer's procedure; `tools/canonicalize.mjs` is a dependency-free reference implementation that CI checks byte for byte against the vectors and against a live production receipt.

1. Take the frozen signed field list for the receipt's `canonicalization` value. For `jcs_v2` that is the 18 `jcs_v1` fields (`id`, `companyId`, `idemKey`, `agentId`, `runId`, `requestJson`, `inputHash`, `status`, `riskTier`, `policyVersion`, `reasonCodes`, `summary`, `receiptVersion`, `canonicalization`, `signatureAlg`, `signatureKeyId`, `expiresAt`, `createdAt`) plus `deciderId`, `deciderDisplay`, `deciderAuthMethod`, `resolutionType`, `attributionConfidence`, `scope`. For `jcs_v3` it is the 22 fields of section 3.4.
2. Copy each listed field whose value is neither `undefined` nor `null`. Skip the others entirely. This is why absent and null are the same thing in a payload, and why `deciderAuthMethod` and `resolutionType` are missing rather than null on some receipts.
3. Serialize `Date` values as ISO 8601 UTC with milliseconds. All other values are copied as they are: `receiptVersion` stays an integer, `requestJson` and `reasonCodes` stay strings.
4. Sort object keys lexicographically, recursively. (The payload is flat; the recursion matters for implementations that canonicalize nested objects.)
5. Serialize with `JSON.stringify` semantics: no whitespace, standard JSON string escaping.
6. UTF-8 encode. These are the **canonical bytes**. The issuer stores them as `signedPayloadBytes` and publishes them as `payload_bytes_b64`.

`jcs_v2` differs from `jcs_v1`, and `jcs_v3` from `jcs_v2`, only in the field list (step 1). Steps 2 through 6 are identical for all three, and every receipt verifies forever under the list its own `canonicalization` names. All three lists are frozen: a new signed field requires `jcs_v4` (see `VERSIONING.md`). The two `jcs_v3` additions, `requestCommitment` and `publicProjectionJson`, are strings and are copied as they are, as `requestJson` was.

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

A `jcs_v3` receipt uses the same envelope, with `receipt_version` 3 and `canonicalization` `jcs_v3`. Its payload bytes carry no request content beyond the public projection, so they can be published for every lane. The request and its salt are not part of the envelope (3.5).

### 6.2 Verify procedure

A conformant verifier performs these steps in order and stops at the first failure.

1. Parse the envelope. Require `artifact.receipt_id`, `key_id`, `alg`, `signed_payload_hash`, `signature_b64`, `payload_bytes_b64` as strings; require `alg` to be `ed25519`. Otherwise **malformed**.
2. Base64-decode `payload_bytes_b64`. Compute `SHA-256` over the bytes. If the lowercase hex digest differs from `signed_payload_hash`: **payload hash mismatch**.
3. Parse the bytes as JSON. Require an object whose `signatureKeyId` equals `key_id`. Otherwise **malformed**.
4. If the parsed object's `canonicalization` names a version the verifier does not implement: **canonicalization unsupported** (section 4). Stop, and do not report tampering. Otherwise re-canonicalize the parsed object under its own `canonicalization`. If the result differs from the decoded bytes: **canonical mismatch**. The bytes were not produced by this specification.
5. Resolve the public key for `key_id` from the key set. Missing: **key not found**. `status: revoked`: **key revoked**.
6. Base64-decode `signature_b64`; require 64 bytes. Verify Ed25519 over the 32-byte digest from step 2 with the resolved key. Failure: **signature invalid**.
7. For `jcs_v3`, apply section 6.7. Its step 1 is required. Its step 2 runs when the verifier holds the request and its salt.
8. Report success with the decoded payload. Report `status` and the decider fields to the caller. Report expiry (`expiresAt` before now) as information, not as a verification failure.

`tools/verify.mjs` implements exactly this and exits `0` verified, `1` signature invalid, `2` key not found or revoked, `3` malformed, `4` hash or canonical mismatch, `8` canonicalization or projection tag unsupported, `9` projection not allowed, `10` commitment not opened (section 6.7).

### 6.3 Schema validation

After step 8 a verifier SHOULD validate the payload against the schema for its version (`schema/receipt-v2.json` for `jcs_v2`, `schema/receipt-v3.json` for `jcs_v3`). For `jcs_v2` it SHOULD also check that `requestJson` parses to an object equal to its own canonical serialization. For both, it SHOULD check that `reasonCodes`, when present, parses to an array of strings. A schema failure on a receipt that passed step 6 is a policy failure (an unexpected value, an unknown decider form), not a signature failure, and SHOULD be reported as such.

### 6.4 What verification proves

Success proves that the bytes were signed by the holder of the private key for `key_id` and are unchanged, and therefore that the decision, decider, policy version, action snapshot, and timestamps inside them are what the issuer committed to.

It does not prove that the action executed or succeeded (section 3.2; an execution attestation, section 9, records what the issuer observed), that the decision was correct, that the receipt is still redeemable, or that the receipt covers the action in front of you unless you compared `requestJson` and `inputHash` to it (section 3.3), or, for `jcs_v3`, the projection or the opened request.

For a `jcs_v3` receipt, the proof depends on what the verifier holds:

- **Anyone with the artifact** learns the decision, the decider, the policy version, the expiry, the time, the projected facts, and that the issuer committed to exactly one request. It learns nothing else about that request, and it cannot check that the projection was built from it. To decide whether the receipt covers an action, it compares the projected commit SHA, environment, capability, tool and operation.
- **The holder of the request and its salt** (section 6.7, step 2) also proves that the committed request is exactly that text and that the projection was built from it by the published rule.

### 6.5 Denials

A `DENIED` receipt verifies with the same procedure. Authenticity and outcome are separate axes: the issuer's public surfaces render a signed denial as an **authentic signature with a DENIED decision**, never as an authorization and never as a failure to verify. Verifiers SHOULD keep the same separation.

### 6.6 Online surfaces

`https://app.permissionprotocol.com/r/<id>` runs the issuer's full verification on every view and withholds a receipt whose bytes do not match its signature. `GET /api/v1/public/receipts/<id>` returns public fields with a `verification` block (`verified`, `signature_intact`, `signature_status`, `state`). `POST /api/v1/receipts/verify` is the tenant-authenticated endpoint CI gates use; it adds scope matching and atomic one-time redemption on top of the cryptographic check.

### 6.7 Verifying a `jcs_v3` receipt

A verifier runs these steps after the signature verifies (section 6.2, step 6). A failure in either step is never reported as verified. A third-party verifier never reports it as tampering either, because the signature is intact (for the issuer's own check, see the end of this section).

**Step 1, the projection check. Every verifier MUST run it.** A third party cannot rebuild the projection without the request, but it can check that the signed projection is a possible output of the build rule for the tag it names. That check catches an issuer defect that would publish a field its tag does not allow.

1. Parse `publicProjectionJson`. If it is not a JSON object, or its top-level `projection` is not a tag the verifier knows: **projection unsupported**. Fail closed; the receipt is unverifiable by that verifier.
2. Require `publicProjectionJson` to equal the canonical serialization of the parsed object (recursively sorted keys, no whitespace).
3. Walk every member of the object except `projection`. Each key MUST lie on a path of the tag's allowlist (3.7), with `[]` positions holding arrays and every other intermediate position holding objects.
4. At each listed leaf, the value MUST satisfy its slot. An **identifier** is a string matching `^[A-Za-z0-9._:/-]{1,128}$`. A **one of** slot holds one of its listed strings. A **value** slot holds a scalar or an array of scalars.
5. A † path MUST NOT appear unless the projection's own `scope.visibility` is `"public"`. The build rule copies `scope.visibility` exactly when it is `public` or `private`, so this is equivalent to the rule applied to the request.
6. A container MUST NOT be empty, except an array element `{}`. An array at a `[]` position MUST be non-empty, hold only objects, and have at least one non-empty element.

Any failure in items 2 to 6 is **projection not allowed**. It is a policy failure: the issuer signed something its own tag forbids, and the receipt MUST NOT be presented as verified.

**Step 2, opening the commitment. A verifier MAY run it when it holds the request text and its salt.**

1. Compute `"sha256:" + hex(SHA-256(salt || UTF-8(request text)))` over the request text exactly as given. If the result is not the signed `requestCommitment`, or the salt is not 32 bytes: **request commitment mismatch**.
2. Rebuild the projection from the request text under the tag that the signed projection names (3.6). If the result is not byte-equal to the signed `publicProjectionJson`: **public projection mismatch**.

A third-party verifier reports a step 2 failure as **commitment not opened**: the signature is intact, and the request or salt it was given is not the one committed to. The issuer is in a different position when it opens the commitment against its own stored request and salt. A mismatch there means its stored record changed after signing, and the issuer reports that receipt as altered, as it would a v2 receipt whose stored fields no longer match their signed bytes.

When step 2 passes, the request text is the one the issuer committed to, and the public projection was built from it by the published rule. A verifier without the request and salt reports the commitment as not opened, and draws no conclusion about the request beyond the projection. The issuer runs step 2 on every verification it performs, before it resolves a key or redeems anything; a projection that passes step 2 also passes step 1.

`tools/verify.mjs` runs step 1 on every `jcs_v3` receipt, and runs step 2 when given `--request <file> --salt <64 hex>`. The file is read as exact text. It exits `8` for an unsupported canonicalization or projection tag, `9` for projection not allowed, and `10` when the supplied request and salt do not open the commitment or do not rebuild the projection.

## 7. Decision and decider semantics

### 7.1 Decisions

`status` is `APPROVED` or `DENIED`. Nothing else is signed. `APPROVED` means the action was authorized under the stated policy version, by the stated decider, at the stated time, for the snapshot in `requestJson`. `DENIED` means it was refused, by policy or by a human, and is signed with the same ceremony. Pending holds (`REQUIRES_APPROVAL`, `REQUIRES_FOUNDER_VETO`), `EXPIRED`, and `ERROR` are lifecycle states of the issuer's row; they carry no signature and are not receipts under this document. (`ALLOW` and `DENY` are the raw vocabulary of the older ledger lane, which is not routed today; verifiers MAY accept them as aliases but will not encounter them from the hosted service.)

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

- `credentialed`: the decider authenticated to the issuer at decision time (session, API key) or is a named policy version. The proof strength of a `session` decider equals the issuer's login: a GitHub OAuth session resolved to tenant membership. Step-up authentication at signing shipped as two `deciderAuthMethod` values, `session_stepup_webauthn` and `session_reauth` (observed on production receipts by 2026-10-03), not as a new field. Execute-lane human approvals signed at the decision are `credentialed` (section 9.1).
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

`prev` is **reserved** for `jcs_v4` and is not emitted today. `jcs_v3` (sections 3.4 to 3.7) is the receipt-privacy change alone and does not carry it. `prev` was evaluated for this document and deferred, because adding it touches more than this repository can carry:

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

Consistency rules a verifier checks after the signature: `succeeded` and `failed` carry `startedAt` and `finishedAt`, with `finishedAt` not before `startedAt`; `unknown` carries neither `finishedAt` nor `outputHash` (if either were known, the outcome would be too). The tenant is not signed: receipt ids are unique, and the receipt's own signature binds what was authorized. `schema/attestation-v1.json` encodes the table.

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
5. Resolve the key and verify Ed25519 over the digest, exactly as 6.2 steps 5 and 6.
6. Require the signed `approvalReceiptId` to equal the envelope's, and apply the 9.2 consistency rules (a failure here is a policy failure, not tampering).

`tools/verify.mjs <attestation.json> <keys.json> --receipt <receipt.json>` implements this.

### 9.6 What an attestation proves

That the issuer recorded this outcome for this authorization at `createdAt`, under its key. `succeeded` and `failed` attest what the action's adapter returned to the issuer, not the state of the target system; `unknown` says the issuer does not know. An authorization with no attestation is "authorized, execution not confirmed by the issuer". The receipt alone still proves only the authorization.

## 10. Lifecycle around the receipt

- **Expiry.** `expiresAt` bounds redemption of an approval by a CI gate or an agent retry. It does not expire the evidence; an expired receipt still verifies.
- **Redemption.** The issuer's verify endpoint can redeem an approval atomically once. Redemption state is unsigned issuer metadata.
- **Idempotency.** A resubmitted execute-lane request with the same `idemKey` returns the existing receipt; a `DENIED` receipt is terminal for its key (kill-switch denials say so in `reasonCodes` with `KILL_SWITCH_DENIAL_TERMINAL`). A changed action under a reused key is refused with a fresh `DENIED` receipt (`APPROVAL_ARTIFACT_MISMATCH`).
- **Re-approval.** An expired deploy-gate approval can be renewed for the unchanged scope; the renewal is a new receipt with its own id and `DEPLOY_GATE_REAPPROVED` in `reasonCodes`, signed by the renewing decider.
- **Revocation.** An unused deploy-gate approval (not redeemed, not merged) can be revoked. The revocation is a new `DENIED` receipt (`rcpt_rev_<uuid>`, `resolutionType` `deny`) whose request names the revoked receipt in `metadata.revokedReceiptId` and whose `summary` is the revoker's reason. The revoked receipt is not re-signed.

## 11. Security considerations

- **Replay.** A valid signature does not prove the receipt is for the action in front of you. Compare `requestJson` and `inputHash` to your own canonical input, and use `idemKey` or the issuer's redemption for one-time execution. For `jcs_v3`, a third party compares the projected commit SHA, environment, capability, tool and operation, and the holder of the request opens the commitment; one-time execution rests on the issuer's redemption.
- **Commitment salt.** A `jcs_v3` salt is as sensitive as the request it opens. With the salt, a guessed request can be confirmed against the commitment. A disclosed salt opens only its own receipt, because every receipt has its own salt.
- **Projection allowlist.** The projection check (6.7, step 1) is how a third party detects an issuer that published a field its tag does not allow. Verifiers MUST run it and MUST fail closed on a tag they do not know.
- **Unsigned metadata.** Anything outside the signed set (section 3.1, or 3.4 for `jcs_v3`) is mutable. Do not decide anything from it.
- **Key compromise.** The issuer holds one production signing key per deployment in environment configuration; its compromise would forge receipts for every tenant until revocation. Verifiers MUST honor `revoked` and SHOULD re-fetch the key set periodically.
- **Canonicalization drift.** Any change to the bytes breaks every existing signature. Implementers MUST test against `test-vectors/` and the live vector; step 4 of the verify procedure exists to catch drift on the issuer's side too.
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
| `v3/approve-human-deploy-gate-private-repo.json` | `jcs_v3`, deploy-gate approval by a named human on a private repository: the `deploy_gate/v1` projection carries no repository identity | verifies |
| `v3/approve-human-deploy-gate-public-repo.json` | `jcs_v3`, the second approval under a two-approver rule on a public repository: the projection carries the † paths, and the recorded decisions without user ids | verifies |
| `v3/approve-human-execute-lane-refund.json` | `jcs_v3`, execute-lane human approval: the `execute/v1` projection carries the intent and action names, never the parameters | verifies |
| `v3/revoke-human-deploy-gate.json` | `jcs_v3`, the private-repository approval revoked: `revocation/v1`, `DENIED` | verifies, decision `DENIED` |
| `v3/tampered-approve-human-deploy-gate-private-repo.json` | the projection's commit SHA edited after signing, hash recomputed | fails at the signature |
| `v3/outside-allowlist-approve-human-execute-lane-refund.json` | validly signed with the test key over a projection that also carries `action.parameters` | signature verifies; fails the projection check (projection not allowed) |
| `v3/openings/openings.json` | commitment openings: each committed request as exact text in `v3/openings/`, a salt, and the expected result of section 6.7 step 2 | four open; another receipt's salt, a reformatted request and a changed request give request commitment mismatch; the outside-allowlist vector gives public projection mismatch |
| `live-deploy-gate-approve.json` | a real production receipt captured from the public artifact endpoint on 2026-09-08 | verifies against `live-keys.json` |
| `keys.json`, `live-keys.json` | the key sets, in the published shape | |

The three generated vectors are produced by `tools/generate-vectors.mjs` from fixed inputs with the repository's test key; CI regenerates them and fails on drift. Their bytes were checked byte for byte against the issuer's own canonicalization code. An implementation claims conformance to this document when it reproduces every expected result above, passes `node --test "test/*.test.mjs"`, and validates each verified payload against `schema/receipt-v2.json` (`jcs_v2` receipts), `schema/receipt-v3.json` (`jcs_v3` receipts) or `schema/attestation-v1.json` (attestations).

The `jcs_v3` vectors use the same key, with fixed published salts in place of the issuer's random ones. On 2026-10-06 the issuer's own signer (`permission-protocol/app` commit `c655e8d5`, with `jcs_v3` switched on) signed the same inputs with the same key and salts. It produced the same canonical bytes, digests, signatures, commitments and projections for every valid `jcs_v3` vector. Its commitment check agreed with every case in `v3/openings/openings.json`. Its projection builder agreed byte for byte with `tools/public-projection.mjs` on 3,536 requests under all three tags: hand-written edge cases, the vector requests, and seeded random requests shaped along the allowlist paths. Every projection it built passed the projection check of section 6.7, and its exported allowlists equal the tables in section 3.7.

## 13. Relationship to other documents

- `RECEIPT-FORMAT-V1.md`: frozen, with errata in 5.5.
- `VERIFY.md`: the nine-line verification and the online paths.
- `MAPPINGS.md`: which fields back which controls.
- `VERSIONING.md`: how this format changes.
- In `permission-protocol/app`: `docs/receipt-standard.md` (the SDK-facing receipt object and status mapping), `permission-protocol-sdk/spec/hashable-payload-v1.md` (`inputHash` on the execute lane), `src/lib/permission-protocol-v1/signing/canonicalize.ts` (the frozen field lists this document transcribes), `src/lib/permission-protocol-v1/signing/public-projection.ts` and `request-commitment.ts` (the `jcs_v3` projection allowlists, build rule and commitment), `docs/trust/design-notes/F2-RECEIPT-V3-PUBLIC-PROJECTION.md` (why `jcs_v3` exists and what it leaves public), `src/lib/permission-router/execution-attestation.ts` (`attest_v1`), `docs/adr/0003-authorization-before-execution.md` (why authorization precedes execution and the outcome is separate).
