// Generates the signed test vectors under test-vectors/ (SPEC.md section 12).
//
//   node tools/generate-vectors.mjs           # write the files
//   node tools/generate-vectors.mjs --check   # fail if the files on disk differ
//
// Deterministic: fixed timestamps and identifiers, and Ed25519 is a
// deterministic signature scheme, so CI can regenerate and diff. The key pair
// is the repository's test key (fixtures/keypair-test), key id pp-test-2026-q2.
// It signs nothing outside this repository.
//
// The three generated receipts mirror three real mint paths of the hosted
// service, field for field:
//   1. approve-human-deploy-gate: a session-authenticated human approves a
//      deploy-gate request (app: src/app/api/v1/deploy-requests/[requestId]/approve/route.ts).
//   2. approve-policy-execute-lane: the router clears a read-only action under
//      policy (app: src/lib/permission-router/execute.ts, policy-evaluation.ts).
//   3. deny-kill-switch-execute-lane: a fresh request denied under a global
//      freeze (app: src/lib/permission-router/kill-switch.ts, execute.ts).
// Plus 4. tampered-approve-human-deploy-gate: vector 1 with one signed field
// edited after signing and the hash recomputed, so the only thing that can
// catch it is the signature.
//
// Execution attestations (SPEC.md section 9, ADR 0003 in the app repo), under
// test-vectors/attestations/: one signed attestation per outcome, each
// referencing an APPROVED execute-lane receipt signed BEFORE the action ran,
// plus a tampered one. Two more receipts mirror the human path of that order:
//   5. approve-human-execute-lane-refund: a human approves a held refund; the
//      authorization is signed at the decision from the live session
//      (credentialed), with the 15-minute redemption window as expiresAt
//      (app: src/lib/permission-router/authorized-execution.ts finalizeApprovedHold).
//   6. approve-human-execute-lane-create-pr: the same for a pull request.
//
// Receipt format v3 (jcs_v3, SPEC.md sections 3.4 to 3.8 and 6.7), under
// test-vectors/v3/: a v3 receipt signs a salted commitment to its private
// request, a public projection of it and, for a decider who stepped up, a
// decider proof, instead of companyId, idemKey, requestJson, inputHash and
// summary. Each request is built the way the issuer's mint path builds it; the
// mint adds the receipt's binding under receiptBinding (its companyId, idemKey
// and inputHash, each a string or null) and the summary under receiptSummary,
// canonicalizes the result and commits it with a fixed test salt (SHA-256 of
// "receipt-spec jcs_v3 test salt: <vector name>"; the issuer draws 32 random
// bytes per receipt). The
// decider proof is built from the stored step-up evidence by the issuer's rule
// (tools/decider-proof.mjs). The commitment, the projection, the proof, the
// bytes and the signature are all computed here from those inputs:
//   v3/approve-human-deploy-gate-private-repo: a human approves a deploy on a
//      private repository after a passkey step-up (webauthn decider proof);
//      the projection carries no repository identity.
//   v3/approve-human-deploy-gate-public-repo: a second approver completes a
//      two-approver rule on a public repository after a fresh GitHub sign-in
//      (reauth decider proof); the projection carries the repository-identity
//      (†) paths and the recorded decisions without user ids.
//   v3/approve-human-execute-lane-refund: a human approves a held refund over
//      a plain session (no proof); the projection carries the intent and action
//      names, never the parameters.
//   v3/revoke-human-deploy-gate: the private-repository approval revoked; the
//      revocation lane, DENIED, the reason committed as the summary. The
//      revocation records no visibility (none was read afresh), so its
//      projection carries no repository identity.
//   v3/tampered-approve-human-deploy-gate-private-repo: the projection's commit
//      SHA edited after signing, hash recomputed: fails at the signature.
//   v3/outside-allowlist-approve-human-execute-lane-refund: validly signed with
//      the test key over a projection that also carries action.parameters,
//      which no issuer may publish: a verifier rejects it (PROJECTION_NOT_ALLOWED).
//   v3/decider-proof-mismatch-approve-human-execute-lane-refund: validly signed
//      over a webauthn decider proof for a decider whose signed auth method is
//      session, which proves no step-up (DECIDER_PROOF_MISMATCH).
//   v3/non-canonical-proof-approve-human-execute-lane-refund: validly signed
//      over a webauthn decider proof that also carries the authenticator's
//      signature counter, a key outside the proof's frozen shape
//      (DECIDER_PROOF_INVALID).
//   v3/no-binding-approve-human-execute-lane-refund: validly signed over a
//      commitment to a request that carries the summary but no receiptBinding,
//      as no issuer's mint writes it. A third party cannot tell (it verifies);
//      the opening fails (RECEIPT_BINDING_MISMATCH).
//   The deploy-gate lane signs deploy_gate/v2 (SPEC.md section 3.7). The two
//   deploy-gate approvals above are frozen history under deploy_gate/v1 and
//   name that tag; these sign the lane's tag:
//   v3/approve-human-deploy-gate-v2-private-repo: a customer protected-path
//      rule holds a change on a private repository; a human approves after a
//      passkey step-up. The projection carries neither the repository identity
//      (†) nor the matched rule's id and version (‡).
//   v3/approve-human-deploy-gate-v2-public-repo: a public repository's
//      approval over a plain session; the projection carries † and ‡.
//   v3/deny-policy-deploy-gate-v2-private-repo: the policy engine denies a
//      change on the private repository; no rule in the projection, and the
//      signed reasonCodes carry the code alone.
//   v3/published-rule-approve-human-deploy-gate-v2-private-repo: validly
//      signed over the private approval's projection with the rule put back:
//      a verifier rejects it (PROJECTION_NOT_ALLOWED).
//   v3/openings/: the private side, which only test vectors publish: each
//      committed request as its exact text, and openings.json, the commitment
//      openings with their salts, the summary and binding values stated beside
//      each, and the expected results.
//
//   node tools/generate-vectors.mjs --inputs <file>
// also writes the mint inputs of every v3 vector an issuer can produce (the
// request before the mint, the summary, the binding, the stored step-up
// evidence, the salt, the decider and the signed fields), so the issuer's own
// signer can sign the
// same inputs with the test key and be compared byte for byte (SPEC.md
// section 12).
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  RECEIPT_SUMMARY_REQUEST_KEY,
  attestationBytes,
  canonicalBytes,
  committedRequestJson,
  outputHash,
  receiptBindingFor,
  requestCommitment,
  signingDigest,
} from "./canonicalize.mjs";
import { deciderProofForSigning } from "./decider-proof.mjs";
import { PROJECTION_TAG_BY_LANE, buildPublicProjection } from "./public-projection.mjs";

const root = new URL("..", import.meta.url).pathname;
const check = process.argv.includes("--check");
const inputsIndex = process.argv.indexOf("--inputs");
const inputsPath = inputsIndex === -1 ? null : process.argv[inputsIndex + 1];
if (inputsIndex !== -1 && !inputsPath) throw new Error("--inputs needs a file path");

const KEY_ID = "pp-test-2026-q2";
const privateKey = createPrivateKey(readFileSync(join(root, "fixtures/keypair-test/private-key.pem")));
const publicRaw = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);

const TENANT = "co_vector_tenant_0001";

// ---------------------------------------------------------------------------
// Helpers that reproduce the issuer's request snapshots.
// ---------------------------------------------------------------------------

function sortKeysDeep(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] !== undefined) sorted[key] = sortKeysDeep(value[key]);
  }
  return sorted;
}
const canonicalJson = (value) => JSON.stringify(sortKeysDeep(value));
const sha256hex = (text) => createHash("sha256").update(text, "utf8").digest("hex");

/** Deploy-gate lane: buildDeployGateReceiptRequestJson (app receipt-payload.ts). */
function deployGateRequestJson({ requestId, expiresAtIso, scope }) {
  return canonicalJson({
    intent: { name: "deploy_gate_approval", summary: "Deploy gate authorization approved", category: "deployment" },
    action: { tool: "github-actions", operation: "deploy" },
    context: { environment: scope.env, reversibility: "REVERSIBLE" },
    scope: {
      repo: scope.repo,
      ref: scope.ref,
      commitSha: scope.commitSha,
      capability: scope.capability,
      env: scope.env,
      workflow: scope.workflow ?? null,
      artifact_digest: scope.artifactDigest ?? null,
    },
    metadata: { deployGateRequestId: requestId },
    policy: { expiresAt: expiresAtIso, decision: null },
    enrichmentSnapshot: null,
  });
}

/** Deploy-gate lane: generateScopeHash (app signing/canonicalize.ts), bare hex. */
function deployGateScopeHash(scope) {
  return sha256hex(canonicalJson({ repo: scope.repo, env: scope.env, ref: scope.ref, commit: scope.commitSha, capability: scope.capability }));
}

/** Execute lane: computeInputHash (app permission-router/canonicalize.ts), sha256: prefix. */
function executeInputHash(req) {
  const hashable = {
    tenantId: req.tenantId,
    actor: { agentId: req.actor.agentId, runId: req.actor.runId },
    intent: req.intent,
    action: req.action,
    context: req.context,
  };
  return `sha256:${sha256hex(canonicalJson(hashable))}`;
}

/** Execute lane: createReceipt stores canonicalize(req) over the whole request. */
function executeRequestJson(req) {
  return canonicalJson(req);
}

// ---------------------------------------------------------------------------
// The receipts, as the stored rows look (null = column is null = absent from
// the signed bytes).
// ---------------------------------------------------------------------------

const deployScope = {
  repo: "acme/billing-api",
  ref: "refs/pull/512/merge",
  commitSha: "a891b24c6d0f3e7a9b1c2d4e5f60718293a4b5c6",
  capability: "deploy:production",
  env: "production",
  workflow: null,
  artifactDigest: null,
};
const deployRequestId = "vec01humanapprove00000001";
const deployCreatedAt = "2026-09-01T14:00:00.000Z";
const deployExpiresAt = "2026-09-01T14:15:00.000Z";
const deployScopeHash = deployGateScopeHash(deployScope);

const approveHuman = {
  id: `rcpt_dg_${deployRequestId}`,
  companyId: TENANT,
  idemKey: `deploy-gate:${deployRequestId}:${deployScopeHash}`,
  agentId: "github-actions",
  runId: "run_18422109331",
  requestJson: deployGateRequestJson({ requestId: deployRequestId, expiresAtIso: deployExpiresAt, scope: deployScope }),
  inputHash: deployScopeHash,
  status: "APPROVED",
  riskTier: null,
  policyVersion: "deploy-gate-v1",
  reasonCodes: JSON.stringify(["DEPLOY_GATE_APPROVED"]),
  summary: "Deploy gate authorization approved",
  deciderId: "user:usr_vec_alice_00000001",
  deciderDisplay: "alice-example",
  deciderAuthMethod: "session",
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  receiptVersion: 2,
  canonicalization: "jcs_v2",
  signatureAlg: "ed25519",
  signatureKeyId: KEY_ID,
  expiresAt: deployExpiresAt,
  createdAt: deployCreatedAt,
};

const readRequest = {
  tenantId: TENANT,
  actor: { agentId: "billing-agent", runId: "run_7f3a9b2c" },
  intent: { name: "ledger:read", summary: "Read the current balance for account acct_demo_123", category: "internal_read" },
  action: { tool: "ledger", operation: "read", parameters: { accountId: "acct_demo_123" } },
  context: { environment: "production", reversibility: "REVERSIBLE" },
  hashes: { inputHash: "" },
};
readRequest.hashes.inputHash = executeInputHash(readRequest);
const readCreatedAt = "2026-09-01T14:05:00.000Z";

const approvePolicy = {
  id: "cmvec02policyclear00000000001",
  companyId: TENANT,
  idemKey: readRequest.hashes.inputHash,
  agentId: "billing-agent",
  runId: "run_7f3a9b2c",
  requestJson: executeRequestJson(readRequest),
  inputHash: readRequest.hashes.inputHash,
  status: "APPROVED",
  riskTier: "A_READONLY",
  policyVersion: "pol_v1_hardcoded",
  reasonCodes: JSON.stringify(["READONLY_OPERATION"]),
  summary: "Read-only action auto-approved",
  deciderId: "system/pp-permission-router",
  deciderDisplay: "Permission Protocol permission router (policy)",
  deciderAuthMethod: "policy",
  resolutionType: null,
  attributionConfidence: "credentialed",
  scope: "production",
  receiptVersion: 2,
  canonicalization: "jcs_v2",
  signatureAlg: "ed25519",
  signatureKeyId: KEY_ID,
  expiresAt: "2026-09-01T15:05:00.000Z", // createdAt + PP_RECEIPT_EXPIRATION_MS default (1 hour)
  createdAt: readCreatedAt,
};

const refundRequest = {
  tenantId: TENANT,
  actor: { agentId: "ops-agent", runId: "run_c0ffee01" },
  intent: { name: "stripe:refund", summary: "Refund charge ch_3Nq8 in full", category: "payments" },
  action: { tool: "stripe", operation: "refund", parameters: { chargeId: "ch_3Nq8", amountCents: 480000 } },
  context: { environment: "production", reversibility: "IRREVERSIBLE" },
  hashes: { inputHash: "" },
};
refundRequest.hashes.inputHash = executeInputHash(refundRequest);

const denyKillSwitch = {
  id: "cmvec03killswitchdeny0000001",
  companyId: TENANT,
  idemKey: refundRequest.hashes.inputHash,
  agentId: "ops-agent",
  runId: "run_c0ffee01",
  requestJson: executeRequestJson(refundRequest),
  inputHash: refundRequest.hashes.inputHash,
  status: "DENIED",
  riskTier: null,
  policyVersion: null,
  reasonCodes: JSON.stringify(["GLOBAL_FREEZE_ACTIVE", "KILL_SWITCH_DENIAL_TERMINAL"]),
  summary:
    "Global freeze is active - all actions denied. This denial is terminal for this request's idempotency key; " +
    "after the kill switch lifts, retry with a new idempotency key (or changed input).",
  deciderId: "system/pp-permission-router",
  deciderDisplay: "Permission Protocol permission router (policy)",
  deciderAuthMethod: "policy",
  resolutionType: null,
  attributionConfidence: "credentialed",
  scope: "production",
  receiptVersion: 2,
  canonicalization: "jcs_v2",
  signatureAlg: "ed25519",
  signatureKeyId: KEY_ID,
  expiresAt: "2026-09-01T15:10:00.000Z",
  createdAt: "2026-09-01T14:10:00.000Z",
};

const refundDecidedAt = "2026-09-01T14:20:00.000Z";
const approveHumanRefund = {
  id: "cmvec05humanrefund00000000001",
  companyId: TENANT,
  idemKey: refundRequest.hashes.inputHash,
  agentId: "ops-agent",
  runId: "run_c0ffee01",
  requestJson: executeRequestJson(refundRequest),
  inputHash: refundRequest.hashes.inputHash,
  status: "APPROVED",
  riskTier: "C_EXECUTE_WITH_APPROVAL",
  policyVersion: "pol_v1_hardcoded",
  reasonCodes: JSON.stringify(["UNREGISTERED_TOOL:stripe", "IRREVERSIBLE:IRREVERSIBLE", "PRODUCTION_ENV", "PRODUCTION_REQUIRES_APPROVAL"]),
  summary: "Production environment requires human approval",
  deciderId: "user:usr_vec_alice_00000001",
  deciderDisplay: "alice-example",
  deciderAuthMethod: "session_stepup_webauthn",
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  receiptVersion: 2,
  canonicalization: "jcs_v2",
  signatureAlg: "ed25519",
  signatureKeyId: KEY_ID,
  expiresAt: "2026-09-01T14:35:00.000Z", // decision + 15-minute redemption window
  createdAt: "2026-09-01T14:12:00.000Z", // the hold was created; signed at the decision
};

const createPrRequest = {
  tenantId: TENANT,
  actor: { agentId: "dev-agent", runId: "run_9a8b7c6d" },
  intent: { name: "github_create_pr:create_pr", summary: "Open a pull request bumping the lockfile", category: "code_change" },
  action: { tool: "github_create_pr", operation: "create_pr", parameters: { repo: "acme/billing-api", head: "deps/lockfile", base: "main", title: "Bump lockfile" } },
  context: { environment: "production", reversibility: "REVERSIBLE" },
  hashes: { inputHash: "" },
};
createPrRequest.hashes.inputHash = executeInputHash(createPrRequest);
const approveHumanCreatePr = {
  id: "cmvec06humancreatepr000000001",
  companyId: TENANT,
  idemKey: createPrRequest.hashes.inputHash,
  agentId: "dev-agent",
  runId: "run_9a8b7c6d",
  requestJson: executeRequestJson(createPrRequest),
  inputHash: createPrRequest.hashes.inputHash,
  status: "APPROVED",
  riskTier: "C_EXECUTE_WITH_APPROVAL",
  policyVersion: "pol_v1_hardcoded",
  reasonCodes: JSON.stringify(["TOOL_EFFECT:write", "PRODUCTION_ENV", "PRODUCTION_REQUIRES_APPROVAL"]),
  summary: "Production environment requires human approval",
  deciderId: "user:usr_vec_alice_00000001",
  deciderDisplay: "alice-example",
  deciderAuthMethod: "session",
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  receiptVersion: 2,
  canonicalization: "jcs_v2",
  signatureAlg: "ed25519",
  signatureKeyId: KEY_ID,
  expiresAt: "2026-09-01T14:45:00.000Z",
  createdAt: "2026-09-01T14:28:00.000Z",
};

// The attestations, as the stored rows look (null = absent from the bytes).
const attestationBase = { attestationVersion: 1, canonicalization: "attest_v1", signatureAlg: "ed25519", signatureKeyId: KEY_ID };
const attestSucceeded = {
  ...attestationBase,
  approvalReceiptId: approvePolicy.id,
  outcome: "succeeded",
  toolCallId: "tc_vec_ledger_read_0001",
  outputHash: outputHash({ accountId: "acct_demo_123", balanceCents: 125000, currency: "USD" }),
  startedAt: "2026-09-01T14:05:00.120Z",
  finishedAt: "2026-09-01T14:05:00.480Z",
  createdAt: "2026-09-01T14:05:00.512Z",
};
const attestFailed = {
  ...attestationBase,
  approvalReceiptId: approveHumanCreatePr.id,
  outcome: "failed",
  toolCallId: null,
  outputHash: null,
  startedAt: "2026-09-01T14:31:10.000Z",
  finishedAt: "2026-09-01T14:31:11.250Z",
  createdAt: "2026-09-01T14:31:11.300Z",
};
const attestUnknown = {
  ...attestationBase,
  approvalReceiptId: approveHumanRefund.id,
  outcome: "unknown",
  toolCallId: null,
  outputHash: null,
  startedAt: null,
  finishedAt: null,
  createdAt: "2026-09-01T14:42:00.000Z", // the reconciler, after the 15-minute stale window
};

// ---------------------------------------------------------------------------
// Sign and wrap.
// ---------------------------------------------------------------------------

function signRow(row) {
  const bytes = canonicalBytes(row, row.canonicalization);
  const digest = signingDigest(bytes);
  const signature = sign(null, digest, privateKey);
  return { bytes, digest, signature };
}

function envelope(row, { description, source }, override = {}) {
  const { bytes, digest, signature } = signRow(row);
  const payloadBytes = override.bytes ?? bytes;
  const payload = JSON.parse(payloadBytes.toString("utf8"));
  return {
    description,
    generated_by: "node tools/generate-vectors.mjs",
    mirrors: source,
    artifact: {
      receipt_id: row.id,
      status: row.status,
      receipt_version: row.receiptVersion,
      canonicalization: row.canonicalization,
      key_id: KEY_ID,
      alg: "ed25519",
      signed_payload_hash: (override.digest ?? digest).toString("hex"),
      signature_b64: (override.signature ?? signature).toString("base64"),
      payload_bytes_b64: payloadBytes.toString("base64"),
      issued_at: row.createdAt,
      expires_at: row.expiresAt,
      redeemed_at: null,
    },
    keys_url: "test-vectors/keys.json",
    verification_hint:
      "Verify SHA-256(payload_bytes) equals signed_payload_hash, then verify the Ed25519 signature over those 32 digest bytes with the public key for key_id.",
    receipt: payload,
  };
}

const humanEnvelope = envelope(approveHuman, {
  description: "APPROVED by a named human over a GitHub session on the deploy-gate (CI/CD) lane. deciderId user:<id>, deciderDisplay the GitHub login, credentialed, allow_once.",
  source: "app src/app/api/v1/deploy-requests/[requestId]/approve/route.ts",
});

// Tampered: edit one signed field after signing, recompute the hash as an
// attacker who controls the envelope would, keep the original signature.
const tamperedRow = { ...approveHuman, summary: "Deploy gate authorization approved. Amount limit raised to unlimited." };
const tamperedBytes = canonicalBytes(tamperedRow, tamperedRow.canonicalization);
const tamperedEnvelope = envelope(
  approveHuman,
  {
    description: "Vector 1 with the summary edited after signing and signed_payload_hash recomputed to match. The signature no longer covers these bytes: verification MUST fail with a signature error, not a hash error.",
    source: "SPEC.md section 6, tamper evidence",
  },
  { bytes: tamperedBytes, digest: signingDigest(tamperedBytes) }
);
tamperedEnvelope.artifact.status = tamperedRow.status;

function attestationEnvelope(row, receiptFile, { description, source }, override = {}) {
  const bytes = attestationBytes(row);
  const digest = signingDigest(bytes);
  const signature = sign(null, digest, privateKey);
  const payloadBytes = override.bytes ?? bytes;
  return {
    description,
    generated_by: "node tools/generate-vectors.mjs",
    mirrors: source,
    receipt_vector: receiptFile,
    attestation_artifact: {
      approval_receipt_id: row.approvalReceiptId,
      outcome: override.outcome ?? row.outcome,
      attestation_version: row.attestationVersion,
      canonicalization: row.canonicalization,
      key_id: KEY_ID,
      alg: "ed25519",
      signed_payload_hash: (override.digest ?? digest).toString("hex"),
      signature_b64: signature.toString("base64"),
      payload_bytes_b64: payloadBytes.toString("base64"),
      issued_at: row.createdAt,
    },
    keys_url: "test-vectors/keys.json",
    verification_hint:
      "Verify the receipt named by approval_receipt_id first (SPEC.md section 6.2). Then verify SHA-256(payload_bytes) equals signed_payload_hash, re-canonicalize the payload under attest_v1, check approvalReceiptId equals that receipt's id, and verify the Ed25519 signature over the digest with the public key for key_id.",
    attestation: JSON.parse(payloadBytes.toString("utf8")),
  };
}

// Tampered: a failed outcome rewritten as succeeded after signing, the hash
// recomputed, the original signature kept.
const tamperedAttestationRow = { ...attestFailed, outcome: "succeeded" };
const tamperedAttestationBytes = attestationBytes(tamperedAttestationRow);

const attestationVectors = {
  "attest-succeeded-policy-execute-lane.json": attestationEnvelope(attestSucceeded, "approve-policy-execute-lane.json", {
    description: "succeeded: the router signed the policy clearance, ran the read once, and attested what the adapter returned. outputHash commits to the canonical output; the output itself is not in the attestation.",
    source: "app src/lib/permission-router/authorized-execution.ts (executeAuthorized), execution-attestation.ts",
  }),
  "attest-failed-human-execute-lane-create-pr.json": attestationEnvelope(attestFailed, "approve-human-execute-lane-create-pr.json", {
    description: "failed: a human authorized the pull request at the decision; the adapter reported failure. The receipt stays APPROVED: it records the authorization, the attestation records the outcome. No output, so no outputHash.",
    source: "app src/lib/permission-router/authorized-execution.ts (executeAuthorized, adapter threw)",
  }),
  "attest-unknown-human-execute-lane-refund.json": attestationEnvelope(attestUnknown, "approve-human-execute-lane-refund.json", {
    description: "unknown: the refund was authorized and claimed for execution, and the process stopped before recording the outcome. After the 15-minute stale window the reconciler records unknown with no start, no finish and no output. Whether the money moved is not known to the issuer; unknown is never upgraded.",
    source: "app src/lib/permission-router/reconcile.ts (reconcileStaleExecution)",
  }),
  "tampered-attest-failed-human-execute-lane-create-pr.json": attestationEnvelope(
    attestFailed,
    "approve-human-execute-lane-create-pr.json",
    {
      description: "The failed attestation with outcome rewritten to succeeded after signing and signed_payload_hash recomputed. Verification MUST fail at the signature.",
      source: "SPEC.md section 9.5, tamper evidence",
    },
    { bytes: tamperedAttestationBytes, digest: signingDigest(tamperedAttestationBytes), outcome: "succeeded" }
  ),
};

const vectors = {
  "approve-human-deploy-gate.json": humanEnvelope,
  "approve-policy-execute-lane.json": envelope(approvePolicy, {
    description: "APPROVED by the deterministic policy engine on the execute lane: a read-only action cleared under pol_v1_hardcoded. deciderAuthMethod policy, no resolutionType, credentialed because the accountable authority is a named policy version.",
    source: "app src/lib/permission-router/execute.ts (allow branch), policy-evaluation.ts, receipt-signing.ts",
  }),
  "deny-kill-switch-execute-lane.json": envelope(denyKillSwitch, {
    description: "DENIED by the kill switch on the execute lane: a fresh request under a global freeze, denied before any policy evaluation, signed with the policy-engine decider. KILL_SWITCH_DENIAL_TERMINAL marks the denial as terminal for this idempotency key.",
    source: "app src/lib/permission-router/kill-switch.ts, execute.ts (step 4.5)",
  }),
  "tampered-approve-human-deploy-gate.json": tamperedEnvelope,
  "approve-human-execute-lane-refund.json": envelope(approveHumanRefund, {
    description: "APPROVED by a named human on the execute lane, signed at the decision from the live session (credentialed) and before the action ran, with the 15-minute redemption window as expiresAt. Its execution attestation is test-vectors/attestations/attest-unknown-human-execute-lane-refund.json.",
    source: "app src/lib/permission-router/authorized-execution.ts (finalizeApprovedHold), receipt-signing.ts",
  }),
  "approve-human-execute-lane-create-pr.json": envelope(approveHumanCreatePr, {
    description: "APPROVED by a named human on the execute lane, signed at the decision before the action ran. Its execution attestation is test-vectors/attestations/attest-failed-human-execute-lane-create-pr.json.",
    source: "app src/lib/permission-router/authorized-execution.ts (finalizeApprovedHold), receipt-signing.ts",
  }),
  "keys.json": {
    description: "Key set for the generated vectors, in the shape of https://app.permissionprotocol.com/.well-known/permission-protocol/keys.json. Test key only; it signs nothing outside this repository.",
    issuer: "https://github.com/permission-protocol/receipt-spec/test-vectors",
    keys: [
      {
        key_id: KEY_ID,
        alg: "ed25519",
        public_key_b64: publicRaw.toString("base64"),
        status: "active",
        created_at: "2026-04-30T00:00:00.000Z",
        revoked_at: null,
      },
    ],
  },
};

// ---------------------------------------------------------------------------
// Receipt format v3 (jcs_v3): SPEC.md sections 3.4 to 3.8 and 6.7.
// ---------------------------------------------------------------------------

/** A file published as its exact text (a committed request), not as JSON. */
class ExactText {
  constructor(text) {
    this.text = text;
  }
}

/** Fixed, published test salt for one vector. The issuer draws 32 CSPRNG bytes per receipt. */
const v3Salt = (name) => createHash("sha256").update(`receipt-spec jcs_v3 test salt: ${name}`, "utf8").digest();

const V3_BASE = { receiptVersion: 3, canonicalization: "jcs_v3", signatureAlg: "ed25519", signatureKeyId: KEY_ID };

/** A fixed lowercase SHA-256 hex digest standing in for one the issuer's passkey ceremony records. */
const evidenceHash = (label) => sha256hex(`receipt-spec jcs_v3 test evidence: ${label}`);
const RP_ID = "app.permissionprotocol.com";
const RP_ORIGIN = "https://app.permissionprotocol.com";

/**
 * Deploy-gate lane under v3: buildDeployGateReceiptRequestJson (app
 * receipt-payload.ts) with scope.visibility recorded, then
 * bindDeployGatePolicy's authorizationBinding (app authorization-binding.ts)
 * and, for a multi-approver rule, the approve route's policyAuthorization,
 * stored as canonical text (requestJsonForReceiptSigning). Finding excerpts
 * are already null, as the builder strips them. A policy denial (`denial`
 * given) is the builder's DENIED shape: the denial intent, and the denial's
 * attribution under metadata.denial.
 */
function deployGateRequestJsonV3({ requestId, expiresAtIso, scope, policyDecision, authorizationBinding, policyAuthorization, enrichmentSnapshot, denial }) {
  return canonicalJson({
    intent: denial
      ? { name: "deploy_gate_denial", summary: "Deploy gate authorization denied", category: "deployment" }
      : { name: "deploy_gate_approval", summary: "Deploy gate authorization approved", category: "deployment" },
    action: { tool: "github-actions", operation: "deploy" },
    context: { environment: scope.env, reversibility: "REVERSIBLE" },
    scope: {
      repo: scope.repo,
      ref: scope.ref,
      commitSha: scope.commitSha,
      capability: scope.capability,
      env: scope.env,
      workflow: scope.workflow ?? null,
      artifact_digest: scope.artifactDigest ?? null,
      visibility: scope.visibility,
    },
    metadata: { deployGateRequestId: requestId, ...(denial ? { denial } : {}) },
    policy: { expiresAt: expiresAtIso, decision: policyDecision, authorizationBinding },
    ...(policyAuthorization ? { policyAuthorization } : {}),
    enrichmentSnapshot,
  });
}

// v3/approve-human-deploy-gate-private-repo
const v3PrivateRequestId = "vec07v3privaterepo000001";
const v3PrivateScope = {
  repo: "acme/payments-core",
  ref: "refs/pull/77/merge",
  commitSha: "3c9e1f0a7b2d4c6e8f0a1b3c5d7e9f1a2b4c6d8e",
  capability: "deploy:production",
  env: "production",
  workflow: ".github/workflows/production-deploy.yml",
  artifactDigest: null,
  visibility: "private",
};
const v3PrivateScopeHash = deployGateScopeHash(v3PrivateScope);
const v3PrivateCreatedAt = "2026-10-06T09:00:00.000Z";
// The passkey step-up the issuer stored for this decision, in the shape its
// passkey verification returns. The signed proof keeps the listed keys only:
// counter, boundRequestId and boundScopeHash (an unsalted hash over the
// private scope) stay behind (SPEC.md section 3.8).
const v3PrivatePasskeyEvidence = {
  method: "webauthn",
  credentialIdHash: evidenceHash("alice passkey credential id"),
  challengeHash: evidenceHash("vec07 assertion challenge"),
  authenticatorDataHash: evidenceHash("vec07 authenticator data"),
  userVerified: true,
  counter: 17,
  rpId: RP_ID,
  origin: RP_ORIGIN,
  boundRequestId: v3PrivateRequestId,
  boundScopeHash: v3PrivateScopeHash,
  reviewGeneration: 1,
  verifiedAt: "2026-10-06T08:59:41.000Z",
};
const v3PrivateExpiresAt = "2026-10-06T09:15:00.000Z";
const v3PrivateRequestJson = deployGateRequestJsonV3({
  requestId: v3PrivateRequestId,
  expiresAtIso: v3PrivateExpiresAt,
  scope: v3PrivateScope,
  policyDecision: {
    ruleId: "hold.protected_path",
    ruleVersion: "outcome-router-v1",
    outcome: "approval_required",
    matchedInputs: {
      changeClass: "protected",
      analysisComplete: true,
      targetBranch: "main",
      defaultBranch: "main",
      changedPaths: ["migrations/2026_10_rotate_ledger_key.sql", "src/ledger/rotate-key.ts"],
      riskSignals: [{ category: "Data", severity: "high", reason: "Rewrites the ledger encryption key column", files: ["migrations/2026_10_rotate_ledger_key.sql"] }],
      findings: [{ ruleId: "protected_path", file: "src/ledger/rotate-key.ts", line: 41, excerpt: null }],
    },
  },
  authorizationBinding: {
    version: 1,
    repository: "acme/payments-core",
    prNumber: 77,
    branch: "main",
    commitSha: "9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d",
    path: ".permission-protocol.yml",
    rulesHash: "5e0c9a7b3d1f8e6c4a2b0d9f7e5c3a1b8d6f4e2c0a9b7d5f3e1c8a6b4d2f0e9c",
  },
  enrichmentSnapshot: {
    summary: "Rotates the ledger encryption key and re-encrypts three tables in place",
    riskSignals: [{ category: "Data", severity: "high", reason: "Re-encrypts ledger rows during the migration" }],
    verificationSteps: [{ step: "Run the rotation against a staging snapshot first", riskTier: "high" }],
    confidenceWarnings: [],
    linkedIssueTitle: "PAY-412: rotate the ledger key before the audit",
    generatedAt: "2026-10-06T08:58:00.000Z",
    consequenceBrief: null,
    policyOutcome: "approval_required",
  },
});
const v3ApprovePrivate = {
  ...V3_BASE,
  id: `rcpt_dg_${v3PrivateRequestId}`,
  companyId: TENANT, // stored, not signed under jcs_v3
  idemKey: `deploy-gate:${v3PrivateRequestId}:${v3PrivateScopeHash}`, // stored, not signed
  inputHash: v3PrivateScopeHash, // stored, not signed
  requestJson: v3PrivateRequestJson, // handed to the mint; the stored, committed text adds the summary
  lane: "deploy_gate",
  // Generated when the lane signed deploy_gate/v1: this vector is frozen
  // history under that tag, so it names its tag instead of the lane's.
  projectionTag: "deploy_gate/v1",
  agentId: "github-actions",
  runId: "run_18533200417",
  status: "APPROVED",
  riskTier: null,
  policyVersion: "deploy-gate-v1",
  reasonCodes: JSON.stringify(["DEPLOY_GATE_APPROVED"]),
  summary: "Deploy gate authorization approved",
  deciderId: "user:usr_vec_alice_00000001",
  deciderDisplay: "alice-example",
  deciderAuthMethod: "session_stepup_webauthn",
  stepUpEvidence: v3PrivatePasskeyEvidence, // stored beside the decision, not signed; the proof is built from it
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  expiresAt: v3PrivateExpiresAt,
  createdAt: v3PrivateCreatedAt,
};

// v3/approve-human-deploy-gate-public-repo
const v3PublicRequestId = "vec08v3publicrepo0000001";
const v3PublicScope = {
  repo: "acme/open-sdk",
  ref: "refs/pull/1204/merge",
  commitSha: "7f2a4c6e8b0d1f3a5c7e9b1d3f5a7c9e0b2d4f6a",
  capability: "deploy:production",
  env: "production",
  workflow: ".github/workflows/release.yml",
  artifactDigest: "sha256:0d4f7a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b2d4f6a8c0e1b3d5f7a9c2e4b6d8f",
  visibility: "public",
};
const v3PublicScopeHash = deployGateScopeHash(v3PublicScope);
const v3PublicCreatedAt = "2026-10-06T10:30:00.000Z";
const v3PublicExpiresAt = "2026-10-06T10:45:00.000Z";
const v3PolicyCommit = "2c4e6a8b0d1f3a5c7e9b1d3f5a7c9e2b4d6f8a0c";
const v3PublicRequestJson = deployGateRequestJsonV3({
  requestId: v3PublicRequestId,
  expiresAtIso: v3PublicExpiresAt,
  scope: v3PublicScope,
  policyDecision: {
    ruleId: "hold.repo_policy_rule",
    ruleVersion: `release-approvers@${v3PolicyCommit}`,
    outcome: "approval_required",
    matchedInputs: {
      changeClass: "protected",
      analysisComplete: true,
      targetBranch: "main",
      defaultBranch: "main",
      changedPaths: ["packages/sdk/package.json", "packages/sdk/src/client.ts"],
      repoPolicy: {
        rule: { id: "release-approvers", rationale: "Every SDK release needs two maintainers", paths: ["packages/sdk/**"] },
        matchedFiles: ["packages/sdk/package.json", "packages/sdk/src/client.ts"],
      },
      approvalRequirements: [{ ruleId: "release-approvers", required: 2, approvers: ["user:usr_vec_alice_00000001", "user:usr_vec_bob_00000002"] }],
    },
  },
  authorizationBinding: {
    version: 1,
    repository: "acme/open-sdk",
    prNumber: 1204,
    branch: "main",
    commitSha: v3PolicyCommit,
    path: ".permission-protocol.yml",
    rulesHash: "a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3",
  },
  policyAuthorization: {
    version: 3,
    round: 1,
    repo: "acme/open-sdk",
    headSha: v3PublicScope.commitSha,
    branch: "main",
    policyBlob: "4d6f8a0c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f",
    policyRef: v3PolicyCommit,
    evaluatorVersion: "rules-v1",
    binding: "e8b0d1f3a5c7e9b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0",
    requirements: [{ ruleId: "release-approvers", required: 2, approvers: ["user:usr_vec_alice_00000001", "user:usr_vec_bob_00000002"] }],
    recordedDecisions: [
      { userId: "user:usr_vec_alice_00000001", displayName: "alice-example", authMethod: "session", at: "2026-10-06T10:21:00.000Z" },
      { userId: "user:usr_vec_bob_00000002", displayName: "bob-example", authMethod: "session_reauth", at: "2026-10-06T10:30:00.000Z" },
    ],
  },
  enrichmentSnapshot: {
    summary: "Bumps the SDK to 4.2.0 and adds request retries to the client",
    riskSignals: [],
    verificationSteps: [{ step: "Run the SDK integration suite against the release build", riskTier: "medium" }],
    confidenceWarnings: [],
    linkedIssueTitle: null,
    generatedAt: "2026-10-06T10:12:00.000Z",
    consequenceBrief: null,
    policyOutcome: "approval_required",
  },
});
const v3ApprovePublic = {
  ...V3_BASE,
  id: `rcpt_dg_${v3PublicRequestId}`,
  companyId: TENANT,
  idemKey: `deploy-gate:${v3PublicRequestId}:${v3PublicScopeHash}`,
  inputHash: v3PublicScopeHash,
  requestJson: v3PublicRequestJson,
  lane: "deploy_gate",
  projectionTag: "deploy_gate/v1", // frozen history, as above
  agentId: "github-actions",
  runId: "run_18533987102",
  status: "APPROVED",
  riskTier: null,
  policyVersion: "deploy-gate-v1",
  reasonCodes: JSON.stringify(["DEPLOY_GATE_APPROVED"]),
  summary: "Deploy gate authorization approved",
  deciderId: "user:usr_vec_bob_00000002",
  deciderDisplay: "bob-example",
  deciderAuthMethod: "session_reauth",
  // The re-authentication the step-up guard accepted: a GitHub sign-in at
  // most maxAgeMs old when the decision was made.
  stepUpEvidence: { method: "reauth", authTime: "2026-10-06T10:27:12.000Z", maxAgeMs: 300000, verifiedAt: "2026-10-06T10:29:58.000Z" },
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  expiresAt: v3PublicExpiresAt,
  createdAt: v3PublicCreatedAt,
};

// v3/approve-human-execute-lane-refund
const v3RefundRequest = {
  tenantId: TENANT,
  actor: { agentId: "ops-agent", runId: "run_c0ffee02" },
  intent: { name: "stripe:refund", summary: "Refund Jane Doe's charge ch_3Qx1 in full after the duplicate billing", category: "payments" },
  action: { tool: "stripe", operation: "refund", parameters: { chargeId: "ch_3Qx1", amountCents: 480000, reason: "duplicate" } },
  context: { environment: "production", reversibility: "IRREVERSIBLE", metadata: { ticket: "SUP-2291", customerEmail: "jane.doe@example.com" } },
  hashes: { inputHash: "" },
};
v3RefundRequest.hashes.inputHash = executeInputHash(v3RefundRequest);
const v3RefundRequestJson = executeRequestJson(v3RefundRequest);
const v3ApproveRefund = {
  ...V3_BASE,
  id: "cmvec09v3humanrefund000000001",
  companyId: TENANT,
  idemKey: v3RefundRequest.hashes.inputHash,
  inputHash: v3RefundRequest.hashes.inputHash,
  requestJson: v3RefundRequestJson,
  lane: "execute",
  agentId: "ops-agent",
  runId: "run_c0ffee02",
  status: "APPROVED",
  riskTier: "C_EXECUTE_WITH_APPROVAL",
  policyVersion: "pol_v1_hardcoded",
  reasonCodes: JSON.stringify(["UNREGISTERED_TOOL:stripe", "IRREVERSIBLE:IRREVERSIBLE", "PRODUCTION_ENV", "PRODUCTION_REQUIRES_APPROVAL"]),
  summary: "Production environment requires human approval",
  deciderId: "user:usr_vec_alice_00000001",
  deciderDisplay: "alice-example",
  deciderAuthMethod: "session",
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  expiresAt: "2026-10-06T11:20:00.000Z", // decision + 15-minute redemption window
  createdAt: "2026-10-06T11:02:00.000Z",
};

// v3/revoke-human-deploy-gate: revokes v3/approve-human-deploy-gate-private-repo
// (app revoke route): the scope is copied from the revoked receipt's request
// without its visibility. A revocation records scope.visibility only from a
// fresh read of the repository, and the route makes none, so its projection
// carries no repository identity. The reason is the summary, committed under
// receiptSummary and also kept in metadata.reason; neither is projected.
// deciderDisplay is the revoker's internal user id, as the route signs it.
const v3RevokeReason = "Migration window moved to Thursday; withdrawn until then";
const { visibility: _revokedVisibility, ...v3RevokeScope } = JSON.parse(v3PrivateRequestJson).scope;
const v3RevokeRequestJson = canonicalJson({
  intent: { name: "authorization_revocation", summary: "Authorization withdrawn" },
  metadata: { revokedReceiptId: v3ApprovePrivate.id, deployGateRequestId: v3PrivateRequestId, reason: v3RevokeReason },
  scope: v3RevokeScope,
});
const v3Revoke = {
  ...V3_BASE,
  id: "rcpt_rev_6f1c2e9a-3b7d-4c5e-8a1f-0d2b4c6e8f0a",
  companyId: TENANT,
  idemKey: `revoke:${v3ApprovePrivate.id}`,
  inputHash: v3PrivateScopeHash,
  requestJson: v3RevokeRequestJson,
  lane: "revocation",
  agentId: "permission-protocol",
  runId: null,
  status: "DENIED",
  riskTier: null,
  policyVersion: null,
  reasonCodes: null,
  summary: v3RevokeReason,
  deciderId: "user:usr_vec_alice_00000001",
  deciderDisplay: "usr_vec_alice_00000001",
  deciderAuthMethod: "session",
  resolutionType: "deny",
  attributionConfidence: "credentialed",
  scope: "production",
  expiresAt: "2026-10-06T10:05:00.000Z", // the signer's default window (one hour); the revoke route passes none
  createdAt: "2026-10-06T09:05:00.000Z",
};

// ---------------------------------------------------------------------------
// deploy_gate/v2 (SPEC.md section 3.7): the deploy-gate lane's tag after Rod's
// decision of 2026-10-08 (F-2 Q-F2-4). deploy_gate/v1 path for path, with the
// matched policy rule's id and version (‡) projected only when the request
// records scope.visibility "public". The rule stays in the committed request.
// ---------------------------------------------------------------------------

const POLICY_FILE = ".permission-protocol.yml";

// v3/approve-human-deploy-gate-v2-private-repo: a customer protected-path
// rule holds a change on a private repository, and a human approves it after
// a passkey step-up. The rule id names an internal control, and so does the
// rule version (<rule id>@<policy commit>): neither is projected.
const v2PrivateRequestId = "vec14v2privaterepo000001";
const v2PrivateScope = {
  repo: "acme/treasury-service",
  ref: "refs/pull/318/merge",
  commitSha: "5b7d9f1a3c5e7a9b1d3f5a7c9e1b3d5f7a9c1e3b",
  capability: "deploy:production",
  env: "production",
  workflow: ".github/workflows/deploy.yml",
  artifactDigest: null,
  visibility: "private",
};
const v2PrivateScopeHash = deployGateScopeHash(v2PrivateScope);
const v2PrivatePolicyCommit = "6d8f0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e";
const v2PrivateExpiresAt = "2026-10-08T14:15:00.000Z";
const v2PrivateRequestJson = deployGateRequestJsonV3({
  requestId: v2PrivateRequestId,
  expiresAtIso: v2PrivateExpiresAt,
  scope: v2PrivateScope,
  policyDecision: {
    ruleId: "hold.repo_protected_path",
    ruleVersion: `wire-transfer-limits@${v2PrivatePolicyCommit}`,
    outcome: "approval_required",
    matchedInputs: {
      changeClass: "repo_policy",
      analysisComplete: true,
      targetBranch: "main",
      defaultBranch: "main",
      changedPaths: ["src/wires/limits.test.ts", "src/wires/limits.ts"],
      riskSignals: [{ category: "Payments", severity: "high", files: ["src/wires/limits.ts"] }],
      repoPolicy: {
        path: POLICY_FILE,
        ref: v2PrivatePolicyCommit,
        status: "loaded",
        rule: { id: "wire-transfer-limits", match: "src/wires/**", rationale: "Wire limits change only with treasury sign-off" },
        matchedFiles: ["src/wires/limits.test.ts", "src/wires/limits.ts"],
      },
    },
  },
  authorizationBinding: {
    version: 1,
    repository: "acme/treasury-service",
    prNumber: 318,
    branch: "main",
    commitSha: v2PrivatePolicyCommit,
    path: POLICY_FILE,
    rulesHash: "b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5",
  },
  enrichmentSnapshot: {
    summary: "Raises the daily wire limit for verified counterparties",
    riskSignals: [{ category: "Payments", severity: "high", reason: "Changes the wire transfer ceiling" }],
    verificationSteps: [{ step: "Confirm the new ceiling with treasury before merging", riskTier: "high" }],
    confidenceWarnings: [],
    linkedIssueTitle: "TRS-88: raise the verified-counterparty wire limit",
    generatedAt: "2026-10-08T13:58:00.000Z",
    consequenceBrief: null,
    policyOutcome: "approval_required",
  },
});
const v2ApprovePrivate = {
  ...V3_BASE,
  id: `rcpt_dg_${v2PrivateRequestId}`,
  companyId: TENANT,
  idemKey: `deploy-gate:${v2PrivateRequestId}:${v2PrivateScopeHash}`,
  inputHash: v2PrivateScopeHash,
  requestJson: v2PrivateRequestJson,
  lane: "deploy_gate", // signs PROJECTION_TAG_BY_LANE.deploy_gate, deploy_gate/v2
  agentId: "github-actions",
  runId: "run_18620344105",
  status: "APPROVED",
  riskTier: null,
  policyVersion: "deploy-gate-v1",
  reasonCodes: JSON.stringify(["DEPLOY_GATE_APPROVED"]),
  summary: "Deploy gate authorization approved",
  deciderId: "user:usr_vec_alice_00000001",
  deciderDisplay: "alice-example",
  deciderAuthMethod: "session_stepup_webauthn",
  stepUpEvidence: {
    method: "webauthn",
    credentialIdHash: evidenceHash("alice passkey credential id"),
    challengeHash: evidenceHash("vec14 assertion challenge"),
    authenticatorDataHash: evidenceHash("vec14 authenticator data"),
    userVerified: true,
    counter: 23,
    rpId: RP_ID,
    origin: RP_ORIGIN,
    boundRequestId: v2PrivateRequestId,
    boundScopeHash: v2PrivateScopeHash,
    reviewGeneration: 1,
    verifiedAt: "2026-10-08T13:59:48.000Z",
  },
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  expiresAt: v2PrivateExpiresAt,
  createdAt: "2026-10-08T14:00:00.000Z",
};

// v3/approve-human-deploy-gate-v2-public-repo: PP's built-in protected-path
// hold on a public repository, approved over a plain session. The rule is
// projected, exactly as deploy_gate/v1 projects it.
const v2PublicRequestId = "vec15v2publicrepo0000001";
const v2PublicScope = {
  repo: "acme/docs-site",
  ref: "refs/pull/96/merge",
  commitSha: "9a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b2d4f6a8c",
  capability: "deploy:production",
  env: "production",
  workflow: ".github/workflows/pages.yml",
  artifactDigest: null,
  visibility: "public",
};
const v2PublicScopeHash = deployGateScopeHash(v2PublicScope);
const v2PublicPolicyCommit = "1f3a5c7e9b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a";
const v2PublicExpiresAt = "2026-10-08T15:15:00.000Z";
const v2PublicRequestJson = deployGateRequestJsonV3({
  requestId: v2PublicRequestId,
  expiresAtIso: v2PublicExpiresAt,
  scope: v2PublicScope,
  policyDecision: {
    ruleId: "hold.protected_path",
    ruleVersion: "outcome-router-v1",
    outcome: "approval_required",
    matchedInputs: {
      changeClass: "protected",
      analysisComplete: true,
      targetBranch: "main",
      defaultBranch: "main",
      changedPaths: [".github/workflows/pages.yml"],
      riskSignals: [{ category: "Delivery", severity: "medium", files: [".github/workflows/pages.yml"] }],
      repoPolicy: { path: POLICY_FILE, ref: v2PublicPolicyCommit, status: "loaded" },
    },
  },
  authorizationBinding: {
    version: 1,
    repository: "acme/docs-site",
    prNumber: 96,
    branch: "main",
    commitSha: v2PublicPolicyCommit,
    path: POLICY_FILE,
    rulesHash: "c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7",
  },
  enrichmentSnapshot: {
    summary: "Moves the docs deploy to the pages workflow's new runner",
    riskSignals: [{ category: "Delivery", severity: "medium", reason: "Edits the deploy workflow" }],
    verificationSteps: [{ step: "Check the preview build before merging", riskTier: "medium" }],
    confidenceWarnings: [],
    linkedIssueTitle: null,
    generatedAt: "2026-10-08T14:52:00.000Z",
    consequenceBrief: null,
    policyOutcome: "approval_required",
  },
});
const v2ApprovePublic = {
  ...V3_BASE,
  id: `rcpt_dg_${v2PublicRequestId}`,
  companyId: TENANT,
  idemKey: `deploy-gate:${v2PublicRequestId}:${v2PublicScopeHash}`,
  inputHash: v2PublicScopeHash,
  requestJson: v2PublicRequestJson,
  lane: "deploy_gate",
  agentId: "github-actions",
  runId: "run_18621907736",
  status: "APPROVED",
  riskTier: null,
  policyVersion: "deploy-gate-v1",
  reasonCodes: JSON.stringify(["DEPLOY_GATE_APPROVED"]),
  summary: "Deploy gate authorization approved",
  deciderId: "user:usr_vec_bob_00000002",
  deciderDisplay: "bob-example",
  deciderAuthMethod: "session",
  resolutionType: "allow_once",
  attributionConfidence: "credentialed",
  scope: "production",
  expiresAt: v2PublicExpiresAt,
  createdAt: "2026-10-08T15:00:00.000Z",
};

// v3/deny-policy-deploy-gate-v2-private-repo: the webhook's policy denial of a
// change on the private repository (app webhook handler.ts
// createPolicyDenialReceipt): the policy engine denies under PP's built-in
// classifier rule, which an override may appeal. Neither the decision's rule
// nor the denial's is projected, and the signed reasonCodes carry the code
// alone, without the rule id (app receipt-payload.ts ruleReasonCodes).
const v2DenyRequestId = "vec16v2policydeny0000001";
const v2DenyScope = {
  ...v2PrivateScope,
  ref: "refs/pull/321/merge",
  commitSha: "2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b",
};
const v2DenyScopeHash = deployGateScopeHash(v2DenyScope);
const v2DenyRuleId = "deny.deterministic_dangerous_diff";
const v2DenyCreatedAt = "2026-10-08T16:00:00.000Z";
const v2DenyExpiresAt = "2027-10-08T16:00:00.000Z"; // createdAt + 365 days, as the webhook signs a denial
const v2DenyReason = "PP denied this change: a credential-shaped assignment in config/payments.env, line 12";
const v2DenyRequestJson = deployGateRequestJsonV3({
  requestId: v2DenyRequestId,
  expiresAtIso: v2DenyExpiresAt,
  scope: v2DenyScope,
  denial: {
    category: "policy",
    reason: v2DenyReason,
    requireNewRequest: true,
    deciderKind: "machine:classifier",
    decisionClass: "classifier",
    ruleId: v2DenyRuleId,
    final: false,
  },
  policyDecision: {
    ruleId: v2DenyRuleId,
    ruleVersion: "outcome-router-v1",
    outcome: "denied",
    matchedInputs: {
      changeClass: "unclassified",
      analysisComplete: true,
      targetBranch: "main",
      defaultBranch: "main",
      changedPaths: ["config/payments.env"],
      riskSignals: [{ category: "Security", severity: "critical", files: ["config/payments.env"] }],
      repoPolicy: { path: POLICY_FILE, ref: v2PrivatePolicyCommit, status: "loaded" },
      findings: [
        {
          predicate: "hardcoded_secret",
          label: "credential-shaped assignment",
          file: "config/payments.env",
          line: 12,
          excerpt: null,
          fix: "Move the value to the secret store and reference it by name",
        },
      ],
    },
  },
  authorizationBinding: {
    version: 1,
    repository: "acme/treasury-service",
    prNumber: 321,
    branch: "main",
    commitSha: v2PrivatePolicyCommit,
    path: POLICY_FILE,
    rulesHash: "b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5",
  },
  enrichmentSnapshot: {
    summary: "Adds the payment processor's sandbox settings",
    riskSignals: [{ category: "Security", severity: "critical", reason: "Commits a credential-shaped value" }],
    verificationSteps: [],
    confidenceWarnings: [],
    linkedIssueTitle: null,
    generatedAt: "2026-10-08T15:59:00.000Z",
    consequenceBrief: null,
    policyOutcome: "denied",
  },
});
const v2DenyPolicy = {
  ...V3_BASE,
  id: `rcpt_dg_${v2DenyRequestId}_denial_policy-1`,
  companyId: TENANT,
  idemKey: `deploy-gate-denial:${v2DenyRequestId}:${v2DenyScopeHash}:policy-1`,
  inputHash: v2DenyScopeHash,
  requestJson: v2DenyRequestJson,
  lane: "deploy_gate",
  agentId: "system/pp-engine",
  runId: "run_18623310984",
  status: "DENIED",
  riskTier: null,
  policyVersion: "deploy-gate-v1",
  // The request records scope.visibility "private": the code alone. A public
  // repository's denial signs ["DEPLOY_GATE_DENIED", <rule id>].
  reasonCodes: JSON.stringify(["DEPLOY_GATE_DENIED"]),
  summary: v2DenyReason,
  deciderId: "system/pp-engine",
  deciderDisplay: "Permission Protocol policy engine",
  deciderAuthMethod: "policy",
  resolutionType: "deny",
  attributionConfidence: "credentialed",
  scope: "production",
  expiresAt: v2DenyExpiresAt,
  createdAt: v2DenyCreatedAt,
};

/**
 * Mint a v3 row as the issuer's signer does (app signing/receipt-v3.ts and
 * decider-proof.ts): add the row's binding to the request under
 * receiptBinding and the summary under receiptSummary, commit to that text
 * with the vector's salt, project it under the lane's tag, and build the
 * decider proof from the stored step-up evidence. The tag is the row's
 * `projectionTag` when it names one, else the one its lane signs today
 * (PROJECTION_TAG_BY_LANE). The bound row stores the
 * committed text as requestJson. `override` replaces the committed request,
 * the projection or the proof, for the deliberately defective vectors only.
 */
function bindV3(row, name, override = {}) {
  const salt = v3Salt(name);
  // The tag the lane signs today, unless the row names the tag it was signed
  // under (the frozen deploy_gate/v1 vectors).
  const projectionTag = row.projectionTag ?? PROJECTION_TAG_BY_LANE[row.lane];
  const binding = receiptBindingFor(row);
  const requestJson = override.requestJson ?? committedRequestJson(row.requestJson, row.summary, binding);
  const deciderProof = Object.prototype.hasOwnProperty.call(override, "deciderProof")
    ? override.deciderProof
    : deciderProofForSigning(row.deciderAuthMethod, row.stepUpEvidence);
  return {
    ...row,
    mintRequestJson: row.requestJson,
    receiptBinding: binding,
    requestJson,
    requestCommitment: requestCommitment(salt, requestJson),
    projectionTag,
    publicProjectionJson: override.publicProjectionJson ?? buildPublicProjection(projectionTag, requestJson),
    deciderProof, // null when the decider did not step up: absent from the bytes
    salt,
  };
}

const V3_HINT =
  "Verify SHA-256(payload_bytes) equals signed_payload_hash, re-canonicalize the payload under jcs_v3, verify the Ed25519 signature over the digest with the public key for key_id, then check that publicProjectionJson is within its tag's allowlist and that deciderProof agrees with deciderAuthMethod (SPEC.md section 6.7). The request holder also opens requestCommitment with the request text and salt, checks the stated summary against the committed receiptSummary, and checks the stated companyId, idemKey and inputHash against the committed receiptBinding.";

function v3Envelope(bound, { description, source, expected }, override = {}) {
  const value = envelope(bound, { description, source }, override);
  value.verification_hint = V3_HINT;
  value.expected = expected;
  value.projection = JSON.parse(value.receipt.publicProjectionJson);
  return value;
}

const v3PrivateBound = bindV3(v3ApprovePrivate, "approve-human-deploy-gate-private-repo");
const v3PublicBound = bindV3(v3ApprovePublic, "approve-human-deploy-gate-public-repo");
const v3RefundBound = bindV3(v3ApproveRefund, "approve-human-execute-lane-refund");
const v3RevokeBound = bindV3(v3Revoke, "revoke-human-deploy-gate");

// Tampered: the projection's commit SHA swapped after signing (still a
// well-formed projection), hash recomputed, original signature kept.
const v3TamperedProjection = JSON.parse(v3PrivateBound.publicProjectionJson);
v3TamperedProjection.scope.commitSha = "0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d";
const v3TamperedBytes = canonicalBytes({ ...v3PrivateBound, publicProjectionJson: canonicalJson(v3TamperedProjection) }, "jcs_v3");

// Outside the allowlist: an issuer defect, signed for real with the test key.
// The projection also carries action.parameters, which execute/v1 never
// publishes. The signature is valid; the projection check must reject it.
const v3LeakName = "outside-allowlist-approve-human-execute-lane-refund";
const v3LeakProjection = JSON.parse(v3RefundBound.publicProjectionJson);
v3LeakProjection.action.parameters = v3RefundRequest.action.parameters;
const v3LeakBound = bindV3({ ...v3ApproveRefund, id: "cmvec10v3leakedparams00000001" }, v3LeakName, {
  publicProjectionJson: canonicalJson(v3LeakProjection),
});

// Decider proof defects, signed for real with the test key. The issuer's mint
// refuses both (it fails closed before signing); a verifier must reject them.
// The passkey evidence alice's execute-lane approvals would store: there
// boundRequestId is the approval id and boundScopeHash the receipt's own id.
const v3RefundPasskeyEvidence = (id, label, counter) => ({
  method: "webauthn",
  credentialIdHash: evidenceHash("alice passkey credential id"),
  challengeHash: evidenceHash(`${label} assertion challenge`),
  authenticatorDataHash: evidenceHash(`${label} authenticator data`),
  userVerified: true,
  counter,
  rpId: RP_ID,
  origin: RP_ORIGIN,
  boundRequestId: `apr_${label}_00000001`,
  boundScopeHash: id,
  verifiedAt: "2026-10-06T11:04:40.000Z",
});
// A webauthn proof signed for a decider whose auth method is session.
const v3ProofMismatchName = "decider-proof-mismatch-approve-human-execute-lane-refund";
const v3ProofMismatchId = "cmvec11v3proofmismatch0000001";
const v3ProofMismatchBound = bindV3({ ...v3ApproveRefund, id: v3ProofMismatchId }, v3ProofMismatchName, {
  deciderProof: deciderProofForSigning("session_stepup_webauthn", v3RefundPasskeyEvidence(v3ProofMismatchId, "vec11", 18)),
});
// A passkey decider whose signed proof also carries the authenticator's
// signature counter, a key outside the proof's frozen shape.
const v3ProofShapeName = "non-canonical-proof-approve-human-execute-lane-refund";
const v3ProofShapeId = "cmvec12v3proofshape0000000001";
const v3ProofShapeEvidence = v3RefundPasskeyEvidence(v3ProofShapeId, "vec12", 19);
const v3ProofShapeBound = bindV3({ ...v3ApproveRefund, id: v3ProofShapeId, deciderAuthMethod: "session_stepup_webauthn" }, v3ProofShapeName, {
  deciderProof: { ...deciderProofForSigning("session_stepup_webauthn", v3ProofShapeEvidence), counter: v3ProofShapeEvidence.counter },
});

// No binding: an issuer defect, signed for real with the test key. The
// committed request carries the summary but no receiptBinding, which every
// jcs_v3 mint writes. Nothing in the signed bytes shows it: a third party
// verifies the receipt; whoever opens the commitment gets
// RECEIPT_BINDING_MISMATCH.
const v3NoBindingName = "no-binding-approve-human-execute-lane-refund";
const v3NoBindingRow = { ...v3ApproveRefund, id: "cmvec13v3nobinding0000000001" };
const v3NoBindingBound = bindV3(v3NoBindingRow, v3NoBindingName, {
  requestJson: canonicalJson({ ...JSON.parse(v3RefundRequestJson), [RECEIPT_SUMMARY_REQUEST_KEY]: v3NoBindingRow.summary }),
});

const v2PrivateBound = bindV3(v2ApprovePrivate, "approve-human-deploy-gate-v2-private-repo");
const v2PublicBound = bindV3(v2ApprovePublic, "approve-human-deploy-gate-v2-public-repo");
const v2DenyBound = bindV3(v2DenyPolicy, "deny-policy-deploy-gate-v2-private-repo");
for (const bound of [v2PrivateBound, v2PublicBound, v2DenyBound]) {
  if (bound.projectionTag !== "deploy_gate/v2") throw new Error(`${bound.id} is not signed under deploy_gate/v2`);
}

// A private rule published: an issuer defect, signed for real with the test
// key. The private deploy_gate/v2 approval's projection with the matched
// rule's id and version put back, as deploy_gate/v1 would publish them. The
// signature is valid; the projection check must reject it.
const v2PublishedRuleName = "published-rule-approve-human-deploy-gate-v2-private-repo";
const v2PublishedRuleProjection = JSON.parse(v2PrivateBound.publicProjectionJson);
const v2PrivateDecision = JSON.parse(v2PrivateRequestJson).policy.decision;
v2PublishedRuleProjection.policy.decision.ruleId = v2PrivateDecision.ruleId;
v2PublishedRuleProjection.policy.decision.ruleVersion = v2PrivateDecision.ruleVersion;
const v2PublishedRuleBound = bindV3({ ...v2ApprovePrivate, id: "rcpt_dg_vec17v2publishedrule0001" }, v2PublishedRuleName, {
  publicProjectionJson: canonicalJson(v2PublishedRuleProjection),
});

const v3Vectors = {
  "approve-human-deploy-gate-private-repo.json": v3Envelope(v3PrivateBound, {
    description: "jcs_v3. APPROVED by a named human on the deploy-gate lane for a private repository, after a passkey step-up. The signed bytes carry no companyId, idemKey, requestJson, inputHash or summary: a salted requestCommitment, a deploy_gate/v1 projection and a webauthn deciderProof instead. companyId, idemKey and inputHash are committed inside the request under receiptBinding, the summary under receiptSummary. scope.visibility is private, so the projection omits every repository-identity (†) path: no repository, ref, workflow, branches, changed paths or PR number. The commit SHA, environment, capability and rule@version stay public. The proof carries three digests, the relying party, the review round and the time; the stored evidence's counter, bound request id and bound scope hash are not signed. The committed request, with the binding under receiptBinding and the summary under receiptSummary, is test-vectors/v3/openings/approve-human-deploy-gate-private-repo.request.json.",
    source: "app src/app/api/v1/deploy-requests/[requestId]/approve/route.ts with PP_RECEIPT_V3=on; signing/receipt-v3.ts, public-projection.ts, request-commitment.ts, decider-proof.ts",
    expected: "verified",
  }),
  "approve-human-deploy-gate-public-repo.json": v3Envelope(v3PublicBound, {
    description: "jcs_v3. APPROVED by the second of two required approvers on the deploy-gate lane for a public repository, after a fresh GitHub sign-in (session_reauth, with a reauth deciderProof: sign-in time, maximum age, decision time). scope.visibility is public, so the projection carries the repository-identity (†) paths. The recorded decisions are projected as display name, auth method and time only; user ids, the rule's rationale, approver lists, the enrichment and the summary stay behind the commitment.",
    source: "app src/app/api/v1/deploy-requests/[requestId]/approve/route.ts (multi-approver rule) with PP_RECEIPT_V3=on",
    expected: "verified",
  }),
  "approve-human-execute-lane-refund.json": v3Envelope(v3RefundBound, {
    description: "jcs_v3. APPROVED by a named human on the execute lane over a plain session, signed at the decision before the action ran. No step-up, so no deciderProof. The execute/v1 projection carries the intent and action names and the two context enums; the tenant, the parameters, the agent's summary, the context metadata and the decision summary stay behind the commitment.",
    source: "app src/lib/permission-router/receipt-signing.ts with PP_RECEIPT_V3=on",
    expected: "verified",
  }),
  "revoke-human-deploy-gate.json": v3Envelope(v3RevokeBound, {
    description: "jcs_v3. The private-repository approval above, revoked: the revocation lane, DENIED, resolutionType deny. The revocation/v1 projection links the revoked receipt and request and carries the revoked request's scope without repository identity: a revocation records scope.visibility only from a fresh read of the repository, and none was made, so it is treated as private. deciderDisplay is the revoker's internal user id, as the revoke route signs it. The reason is free text: it is the summary, committed under receiptSummary, and is neither signed nor projected.",
    source: "app src/app/api/v1/receipts/[receiptId]/revoke/route.ts with PP_RECEIPT_V3=on",
    expected: "verified",
  }),
  "tampered-approve-human-deploy-gate-private-repo.json": v3Envelope(
    v3PrivateBound,
    {
      description: "approve-human-deploy-gate-private-repo with the projection's scope.commitSha replaced after signing and signed_payload_hash recomputed to match. The edited projection is still well formed, so only the signature can catch it: verification MUST fail with a signature error.",
      source: "SPEC.md section 6, tamper evidence",
      expected: "SIGNATURE_INVALID",
    },
    { bytes: v3TamperedBytes, digest: signingDigest(v3TamperedBytes) }
  ),
  [`${v3LeakName}.json`]: v3Envelope(v3LeakBound, {
    description: "A deliberate issuer defect, signed for real with the test key: an execute-lane v3 receipt whose projection also carries action.parameters, which execute/v1 never publishes. The signature verifies; the projection check MUST reject it as PROJECTION_NOT_ALLOWED, a policy failure, not tampering. Opening its commitment with the right request and salt gives PUBLIC_PROJECTION_MISMATCH.",
    source: "SPEC.md section 6.7, projection check",
    expected: "PROJECTION_NOT_ALLOWED",
  }),
  [`${v3ProofMismatchName}.json`]: v3Envelope(v3ProofMismatchBound, {
    description: "A deliberate issuer defect, signed for real with the test key: the execute-lane approval signs deciderAuthMethod session, which proves no step-up, beside a webauthn deciderProof. The proof itself is well formed. The signature verifies; the decider proof check MUST reject it as DECIDER_PROOF_MISMATCH, a policy failure, not tampering. The issuer's mint refuses such a receipt (DECIDER_PROOF_UNEXPECTED).",
    source: "SPEC.md sections 3.8 and 6.7, decider proof check",
    expected: "DECIDER_PROOF_MISMATCH",
  }),
  [`${v3ProofShapeName}.json`]: v3Envelope(v3ProofShapeBound, {
    description: "A deliberate issuer defect, signed for real with the test key: a passkey decider (session_stepup_webauthn) whose webauthn deciderProof also carries the authenticator's signature counter, a key outside the proof's frozen shape. The signature verifies; the decider proof check MUST reject it as DECIDER_PROOF_INVALID, a policy failure, not tampering. The issuer's mint never copies that key.",
    source: "SPEC.md sections 3.8 and 6.7, decider proof check",
    expected: "DECIDER_PROOF_INVALID",
  }),
  [`${v3NoBindingName}.json`]: v3Envelope(v3NoBindingBound, {
    description: "A deliberate issuer defect, signed for real with the test key: an execute-lane v3 approval whose committed request carries the summary but no receiptBinding, which every jcs_v3 mint writes (SPEC.md section 3.5). Nothing in the signed bytes shows it, so a verifier without the request verifies it. Opening its commitment gives RECEIPT_BINDING_MISMATCH: the record cannot be the one the issuer committed.",
    source: "SPEC.md sections 3.5 and 6.7, step 3",
    expected: "verified",
  }),
  "approve-human-deploy-gate-v2-private-repo.json": v3Envelope(v2PrivateBound, {
    description: "jcs_v3 under deploy_gate/v2, the projection the deploy-gate lane signs from permission-protocol/app#691. APPROVED by a named human for a private repository, after a passkey step-up, on a hold by the workspace's own protected-path rule. scope.visibility is private, so the projection omits every repository-identity (†) path and every policy-rule-identity (‡) path: no policy.decision.ruleId or ruleVersion (which here names the customer's rule, wire-transfer-limits, at its policy commit). The decision outcome, the change class, the commit SHA, the policy commit and the rules hash stay public. A verifier reports the rule as withheld and never names policyVersion in its place. The committed request keeps the rule; opening it (test-vectors/v3/openings/approve-human-deploy-gate-v2-private-repo.request.json) shows hold.repo_protected_path@wire-transfer-limits@<policy commit>.",
    source: "app src/app/api/v1/deploy-requests/[requestId]/approve/route.ts with PP_RECEIPT_V3=on, deploy-gate lane on deploy_gate/v2; signing/public-projection.ts",
    expected: "verified",
  }),
  "approve-human-deploy-gate-v2-public-repo.json": v3Envelope(v2PublicBound, {
    description: "jcs_v3 under deploy_gate/v2. APPROVED by a named human over a plain session (no decider proof) for a public repository, on PP's built-in protected-path hold. scope.visibility is public, so the projection carries the repository-identity (†) paths and the matched rule (‡), hold.protected_path@outcome-router-v1, exactly as deploy_gate/v1 would.",
    source: "app src/app/api/v1/deploy-requests/[requestId]/approve/route.ts with PP_RECEIPT_V3=on, deploy-gate lane on deploy_gate/v2",
    expected: "verified",
  }),
  "deny-policy-deploy-gate-v2-private-repo.json": v3Envelope(v2DenyBound, {
    description: "jcs_v3 under deploy_gate/v2. DENIED by the policy engine (system/pp-engine) on the webhook, for a private repository, under PP's built-in classifier rule (appealable: final false). The projection carries the denial's category, decision class, finality and requireNewRequest, and the decision outcome, but neither the decision's rule nor metadata.denial.ruleId (‡). The signed reasonCodes are [\"DEPLOY_GATE_DENIED\"], without the rule id a public repository's denial carries as its second code. A verifier reports the rule as withheld, never the signed policyVersion (deploy-gate-v1) in its place. The engine's reason is the committed summary.",
    source: "app src/app/api/github-app/webhook/handler.ts (createPolicyDenialReceipt) with PP_RECEIPT_V3=on; deploy-gate/receipt-payload.ts ruleReasonCodes",
    expected: "verified",
  }),
  [`${v2PublishedRuleName}.json`]: v3Envelope(v2PublishedRuleBound, {
    description: "A deliberate issuer defect, signed for real with the test key: the private-repository deploy_gate/v2 approval with policy.decision.ruleId and ruleVersion put back into its projection, as deploy_gate/v1 would publish them. scope.visibility is private, so deploy_gate/v2 never emits them. The signature verifies; the projection check MUST reject it as PROJECTION_NOT_ALLOWED, first at policy.decision.ruleId, policy rule identity on a projection whose scope.visibility is not public: a policy failure, not tampering. Opening its commitment with the right request and salt gives PUBLIC_PROJECTION_MISMATCH.",
    source: "SPEC.md sections 3.6, 3.7 and 6.7, projection check",
    expected: "PROJECTION_NOT_ALLOWED",
  }),
};

// The private side. A real issuer never publishes it; it hands a request, its
// salt and the stored summary to the workspace that owns the receipt.
const reformattedPrivateRequest = JSON.stringify(JSON.parse(v3PrivateBound.requestJson), null, 2);
const modifiedRefundRequest = v3RefundBound.requestJson.replace('"amountCents":480000', '"amountCents":480001');
if (modifiedRefundRequest === v3RefundBound.requestJson) throw new Error("modified refund request did not change");

const opening = (receiptVector, requestFile, salt, summary, expected, note, binding) => ({
  receipt_vector: receiptVector,
  request_file: requestFile,
  salt_hex: salt.toString("hex"),
  ...(summary === undefined ? {} : { summary }),
  ...(binding === undefined ? {} : { binding }),
  expected,
  note,
});
const v3Openings = {
  "approve-human-deploy-gate-private-repo.request.json": new ExactText(v3PrivateBound.requestJson),
  "approve-human-deploy-gate-public-repo.request.json": new ExactText(v3PublicBound.requestJson),
  "approve-human-execute-lane-refund.request.json": new ExactText(v3RefundBound.requestJson),
  "revoke-human-deploy-gate.request.json": new ExactText(v3RevokeBound.requestJson),
  "reformatted-approve-human-deploy-gate-private-repo.request.json": new ExactText(reformattedPrivateRequest),
  "modified-approve-human-execute-lane-refund.request.json": new ExactText(modifiedRefundRequest),
  [`${v3NoBindingName}.request.json`]: new ExactText(v3NoBindingBound.requestJson),
  "approve-human-deploy-gate-v2-private-repo.request.json": new ExactText(v2PrivateBound.requestJson),
  "approve-human-deploy-gate-v2-public-repo.request.json": new ExactText(v2PublicBound.requestJson),
  "deny-policy-deploy-gate-v2-private-repo.request.json": new ExactText(v2DenyBound.requestJson),
  "openings.json": {
    description:
      "Commitment openings for the jcs_v3 vectors (SPEC.md section 6.7, step 3). Each case names a receipt vector in test-vectors/v3/, a request file in this directory (its exact text: the commitment covers it byte for byte, so read it without reformatting), a 32-byte salt in hex and, when present, summary: the summary the issuer states for the receipt beside the request (a string, or null for none), which must equal the committed receiptSummary; and binding: the companyId, idemKey and inputHash the issuer states for the receipt (any subset; the owner fields company_id, idem_key and input_hash), each of which must equal the committed receiptBinding value. A case without summary or binding states none and compares nothing, but the committed request must still carry a receiptBinding as the mint writes it. expected is the result of the opening step alone: opened, REQUEST_COMMITMENT_MISMATCH, COMMITTED_SUMMARY_MISMATCH, RECEIPT_BINDING_MISMATCH or PUBLIC_PROJECTION_MISMATCH. These salts are fixed test values; an issuer draws 32 random bytes per receipt and never publishes them.",
    generated_by: "node tools/generate-vectors.mjs",
    cases: [
      opening("approve-human-deploy-gate-private-repo.json", "approve-human-deploy-gate-private-repo.request.json", v3PrivateBound.salt, v3PrivateBound.summary, "opened", "The committed request and its salt reproduce requestCommitment, the stated summary is the committed receiptSummary, the stated companyId, idemKey and inputHash are the committed receiptBinding, and the deploy_gate/v1 projection rebuilt from the request equals the signed one.", v3PrivateBound.receiptBinding),
      opening("approve-human-deploy-gate-public-repo.json", "approve-human-deploy-gate-public-repo.request.json", v3PublicBound.salt, v3PublicBound.summary, "opened", "As above, for the public repository."),
      opening("approve-human-execute-lane-refund.json", "approve-human-execute-lane-refund.request.json", v3RefundBound.salt, v3RefundBound.summary, "opened", "As above, under execute/v1."),
      opening("revoke-human-deploy-gate.json", "revoke-human-deploy-gate.request.json", v3RevokeBound.salt, v3RevokeBound.summary, "opened", "As above, under revocation/v1: the revocation reason is the committed summary."),
      opening("approve-human-execute-lane-refund.json", "approve-human-execute-lane-refund.request.json", v3RefundBound.salt, undefined, "opened", "No summary stated: the opening checks the commitment and the projection, and reports the committed summary without comparing it."),
      opening("approve-human-deploy-gate-private-repo.json", "approve-human-deploy-gate-private-repo.request.json", v3PublicBound.salt, undefined, "REQUEST_COMMITMENT_MISMATCH", "The right request with another receipt's salt."),
      opening("approve-human-deploy-gate-private-repo.json", "reformatted-approve-human-deploy-gate-private-repo.request.json", v3PrivateBound.salt, undefined, "REQUEST_COMMITMENT_MISMATCH", "The same request object pretty-printed: the commitment covers the exact text, never a re-serialization."),
      opening("approve-human-execute-lane-refund.json", "modified-approve-human-execute-lane-refund.request.json", v3RefundBound.salt, undefined, "REQUEST_COMMITMENT_MISMATCH", "The right salt with one byte of the request changed (amountCents 480000 to 480001), a field the projection does not show."),
      opening("approve-human-deploy-gate-private-repo.json", "approve-human-deploy-gate-private-repo.request.json", v3PrivateBound.salt, `${v3PrivateBound.summary}. Amount limit raised to unlimited.`, "COMMITTED_SUMMARY_MISMATCH", "The commitment opens, but the stated summary was edited after signing: it is not the committed receiptSummary. The summary is not in the signed bytes, so only an opening catches this."),
      opening("revoke-human-deploy-gate.json", "revoke-human-deploy-gate.request.json", v3RevokeBound.salt, null, "COMMITTED_SUMMARY_MISMATCH", "The commitment opens, but the summary is stated as none while the request commits the revocation reason."),
      opening("approve-human-execute-lane-refund.json", "approve-human-execute-lane-refund.request.json", v3RefundBound.salt, v3RefundBound.summary, "RECEIPT_BINDING_MISMATCH", "The commitment opens and the summary holds, but the stated companyId is another workspace's: the stored record says the receipt belongs to a workspace the commitment does not bind. jcs_v2 signed companyId; jcs_v3 commits it under receiptBinding, so only an opening catches this.", { ...v3RefundBound.receiptBinding, companyId: "co_vector_tenant_0002" }),
      opening(`${v3NoBindingName}.json`, `${v3NoBindingName}.request.json`, v3NoBindingBound.salt, v3NoBindingBound.summary, "RECEIPT_BINDING_MISMATCH", "The commitment opens and the summary holds, but the committed request carries no receiptBinding, which every jcs_v3 mint writes: the record cannot be the one the issuer committed. No binding needs to be stated for this to fail."),
      opening(`${v3LeakName}.json`, "approve-human-execute-lane-refund.request.json", v3LeakBound.salt, v3LeakBound.summary, "PUBLIC_PROJECTION_MISMATCH", "The commitment opens and the summary holds, but the execute/v1 projection rebuilt from the request lacks the action.parameters the defective receipt signed."),
      opening("approve-human-deploy-gate-v2-private-repo.json", "approve-human-deploy-gate-v2-private-repo.request.json", v2PrivateBound.salt, v2PrivateBound.summary, "opened", "deploy_gate/v2 on a private repository: the commitment opens, the stated summary and binding are the committed ones, and the deploy_gate/v2 projection rebuilt from the request equals the signed one, without the matched rule. The opened request records it: policy.decision is hold.repo_protected_path at wire-transfer-limits@<policy commit>, which the owner sees and the public bytes do not carry.", v2PrivateBound.receiptBinding),
      opening("approve-human-deploy-gate-v2-public-repo.json", "approve-human-deploy-gate-v2-public-repo.request.json", v2PublicBound.salt, v2PublicBound.summary, "opened", "deploy_gate/v2 on a public repository: the projection rebuilt from the request carries the repository identity and the matched rule."),
      opening("deny-policy-deploy-gate-v2-private-repo.json", "deny-policy-deploy-gate-v2-private-repo.request.json", v2DenyBound.salt, v2DenyBound.summary, "opened", "The private repository's policy denial under deploy_gate/v2: the engine's reason is the committed summary, and the opened request records the rule (deny.deterministic_dangerous_diff) on the decision and on metadata.denial."),
      opening(`${v2PublishedRuleName}.json`, "approve-human-deploy-gate-v2-private-repo.request.json", v2PublishedRuleBound.salt, v2PublishedRuleBound.summary, "PUBLIC_PROJECTION_MISMATCH", "The commitment opens and the summary holds, but the deploy_gate/v2 projection rebuilt from the request has no policy.decision.ruleId or ruleVersion, which the defective receipt signed."),
    ],
  },
};

const allVectors = {
  ...vectors,
  ...Object.fromEntries(Object.entries(attestationVectors).map(([name, value]) => [`attestations/${name}`, value])),
  ...Object.fromEntries(Object.entries(v3Vectors).map(([name, value]) => [`v3/${name}`, value])),
  ...Object.fromEntries(Object.entries(v3Openings).map(([name, value]) => [`v3/openings/${name}`, value])),
};

// conformance/expected-canonical-bytes.txt: the v1 fixture digests it has
// always published (RECEIPT-FORMAT-V1.md), then the SHA-256 of the canonical
// bytes of every jcs_v3 vector, path first, generated here so it cannot drift.
const conformancePath = join(root, "conformance", "expected-canonical-bytes.txt");
const conformanceV1 = readFileSync(conformancePath, "utf8").split("\n").filter((line) => line && !line.startsWith("test-vectors/"));
const conformanceText = `${[
  ...conformanceV1,
  ...Object.entries(v3Vectors).map(([name, value]) => `test-vectors/v3/${name} ${signingDigest(Buffer.from(value.artifact.payload_bytes_b64, "base64")).toString("hex")}`),
].join("\n")}\n`;

let drift = 0;
if (!check) {
  mkdirSync(join(root, "test-vectors", "attestations"), { recursive: true });
  mkdirSync(join(root, "test-vectors", "v3", "openings"), { recursive: true });
}
const outputs = [
  ...Object.entries(allVectors).map(([name, value]) => [
    `test-vectors/${name}`,
    // A committed request is published as its exact text: no reformatting and
    // no trailing newline, because the commitment covers it byte for byte.
    value instanceof ExactText ? value.text : `${JSON.stringify(value, null, 2)}\n`,
  ]),
  ["conformance/expected-canonical-bytes.txt", conformanceText],
];
for (const [relative, text] of outputs) {
  const path = join(root, relative);
  if (check) {
    const current = existsSync(path) ? readFileSync(path, "utf8") : null;
    if (current !== text) {
      drift += 1;
      console.error(`DRIFT ${relative}: regenerate with node tools/generate-vectors.mjs`);
    }
  } else {
    writeFileSync(path, text);
    console.log(`wrote ${relative}`);
  }
}

// The mint inputs of every v3 vector an issuer can produce, for signing them
// with the issuer's own signer and comparing byte for byte (SPEC.md section 12).
if (inputsPath) {
  const issuable = Object.entries({
    "approve-human-deploy-gate-private-repo.json": v3PrivateBound,
    "approve-human-deploy-gate-public-repo.json": v3PublicBound,
    "approve-human-execute-lane-refund.json": v3RefundBound,
    "revoke-human-deploy-gate.json": v3RevokeBound,
    "approve-human-deploy-gate-v2-private-repo.json": v2PrivateBound,
    "approve-human-deploy-gate-v2-public-repo.json": v2PublicBound,
    "deny-policy-deploy-gate-v2-private-repo.json": v2DenyBound,
  }).map(([name, bound]) => ({
    vector: `test-vectors/v3/${name}`,
    lane: bound.lane,
    // The tag to sign under: the frozen deploy_gate/v1 vectors name theirs,
    // the others take the one their lane signs today.
    projection_tag: bound.projectionTag,
    salt_hex: bound.salt.toString("hex"),
    request_json: bound.mintRequestJson,
    summary: bound.summary,
    receipt_binding: bound.receiptBinding,
    step_up_evidence: bound.stepUpEvidence ?? null,
    fields: Object.fromEntries(
      ["id", "companyId", "idemKey", "agentId", "runId", "inputHash", "status", "riskTier", "policyVersion", "reasonCodes", "createdAt", "expiresAt"].map((field) => [field, bound[field] ?? null])
    ),
    decider: Object.fromEntries(
      ["deciderId", "deciderDisplay", "deciderAuthMethod", "resolutionType", "attributionConfidence", "scope"].map((field) => [field, bound[field] ?? null])
    ),
  }));
  writeFileSync(
    inputsPath,
    `${JSON.stringify({ description: "jcs_v3 mint inputs, from node tools/generate-vectors.mjs --inputs", key_id: KEY_ID, private_key_pem: "fixtures/keypair-test/private-key.pem", vectors: issuable }, null, 2)}\n`
  );
  console.log(`wrote mint inputs to ${inputsPath}`);
}

if (check) {
  if (drift) process.exit(1);
  console.log("vectors match their generator");
}
