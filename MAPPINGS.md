# Control mappings

How a signed receipt relates to the controls buyers are asked about. Three statuses, used the same way on every row:

- **implements**: the receipt, or the gate that issues it, is the control for approval-gated actions.
- **provides evidence for**: the receipt is the artifact an assessor would ask for to show the control operated; the control itself lives elsewhere in the customer's stack.
- **not addressed**: outside what a receipt can show.

Permission Protocol implements controls and produces evidence. It is not a conformance target, and nothing here is a certification, a compliance claim, or a statement that any framework's requirement is met. The site pages linked below carry the full mappings and are the source of record; this appendix pins the receipt fields each mapping relies on so an assessor can go from a control to a field to a byte.

## AIUC-1 (July 15, 2026 numbering)

Full mapping: https://permissionprotocol.com/compliance/aiuc-1

| Control | Status | Receipt fields relied on |
|---|---|---|
| A003.1 Data access scoping | provides evidence for | `requestJson` (the exact action context the decider saw), `inputHash` |
| A003.2 Agent identity management | provides evidence for | `agentId`, `runId`; identity source stays the customer's IdP |
| A003.3 Agent access and permissions management | provides evidence for | `policyVersion`, `status`, `deciderAuthMethod` |
| B006 Contextual access controls | implements (approval-gated actions) | `inputHash` bound to `status` and `deciderId` |
| C007 Flag high-risk outputs for human review | provides evidence for | `status`, `deciderId`, `createdAt`; the queue and latency report are hosted features, not receipt fields |
| D003 Restrict unsafe tool calls | implements (approval-gated actions) | `status: DENIED` receipts are first-class, signed evidence |
| E004 Assign accountability | provides evidence for | `deciderId`, `deciderDisplay`, `attributionConfidence` (see the attribution note below) |
| E015 Log model activity | implements (gated actions only) | the whole signed payload |

## CSA Agentic Trust Framework (ATF v0.9)

Full mapping, requirement by requirement: https://permissionprotocol.com/atf

| Requirement | Status | Receipt fields relied on |
|---|---|---|
| I-1 Unique identifier | provides evidence for | `agentId` |
| I-2 Credential binding | implements | `deciderId`, `deciderDisplay`, `deciderAuthMethod`, `attributionConfidence` inside the signed bytes |
| I-3 Ownership chain | provides evidence for | `deciderId`; no agent-to-owner registry exists in the product |
| I-4 Purpose declaration | provides evidence for | `requestJson.intent`, `summary` |
| I-5 Capability manifest | not addressed | |
| B-1 Structured logging | implements | the whole signed payload; `reasonCodes`, `policyVersion` |
| B-2 Action attribution | implements | `agentId`, `runId`, `deciderId` (granularity per lane; see below) |
| B-3 Behavioral baseline, B-4 Anomaly detection | not addressed | |
| B-5 Explainability | provides evidence for | `summary`, `reasonCodes`, `requestJson` |
| S-2 Action boundaries, S-4 Transaction limits | implements (approval-gated actions) | `riskTier`, `policyVersion`, `status` |
| R-2 Kill switch | implements | `status: DENIED` with `reasonCodes` containing `GLOBAL_FREEZE_ACTIVE`, `AGENT_PAUSED`, or `CAPABILITY_PAUSED` plus `KILL_SWITCH_DENIAL_TERMINAL` |
| R-4 Rollback evidence | provides evidence for | `requestJson`, `createdAt` |
| Remaining requirements | as stated on the page | |

## NIST AI RMF

Full mapping: https://permissionprotocol.com/compliance/nist

| Function and subcategory | Status | Receipt fields relied on |
|---|---|---|
| GOVERN GV.OC, GV.PO, GV.RR | provides evidence for | `deciderId`, `deciderDisplay`, `policyVersion` |
| MANAGE MG.AN, MG.RR, MG.MT | implements (gated actions) | `status`, `riskTier`, `reasonCodes`, `createdAt` |
| MEASURE MS.AN, MS.EV, MS.TR | provides evidence for | the whole signed payload; `signatureAlg`, `signatureKeyId` for MS.TR |

ISO/IEC 42001 is not mapped yet. When the site page lands, a row set is added here with the same three statuses.

## The attribution note every assessor should read

`deciderId` names the decider at the granularity the mint path had at signing time:

- Deploy-gate lane (CI/CD): `user:<id>` with the GitHub login in `deciderDisplay`, `deciderAuthMethod: session`, `attributionConfidence: credentialed`. This names a human.
- Execute lane (agent and tool calls through the router): since 2026-09-08, a human decision binds `user:<id>` with the GitHub handle in `deciderDisplay`, `attributionConfidence: heuristic` (the identity is read from the approval record at signing time, not captured at the signature). This names a human. Receipts signed before that date bind `role/human-approver` or `role/founder` and are never re-signed, and the API-key lane still binds `role/api-key-approver`, so an assessor will meet both forms. `SPEC.md` 7.4 states the difference.
- Policy decisions: `system/pp-permission-router`, `system/pp-policy-engine`, or `system/pp-engine`. To an assessor this is a signed statement that **no human approved this**; the named `policyVersion` is the accountable authority.
- Demo scope: `demo:<id>`, `unattributed`, signed under a distinct demo key. Never production evidence.

`SPEC.md` section 3 has the field definitions; `test-vectors/` has one signed example of each.
