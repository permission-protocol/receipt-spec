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
// Receipt format v3 (jcs_v3, SPEC.md sections 3.4 to 3.7 and 6.7), under
// test-vectors/v3/: a v3 receipt signs a salted commitment to its private
// request and a public projection of it instead of companyId, idemKey,
// requestJson and inputHash. Each request is built the way the issuer's mint
// path builds it, stored as canonical text, and committed with a fixed test
// salt (SHA-256 of "receipt-spec jcs_v3 test salt: <vector name>"; the issuer
// draws 32 random bytes per receipt). The commitment, the projection, the
// bytes and the signature are all computed here from those inputs:
//   v3/approve-human-deploy-gate-private-repo: a human approves a deploy on a
//      private repository; the projection carries no repository identity.
//   v3/approve-human-deploy-gate-public-repo: a second approver completes a
//      two-approver rule on a public repository; the projection carries the
//      repository-identity (†) paths and the recorded decisions without user ids.
//   v3/approve-human-execute-lane-refund: a human approves a held refund; the
//      projection carries the intent and action names, never the parameters.
//   v3/revoke-human-deploy-gate: the private-repository approval revoked; the
//      revocation lane, DENIED, the reason signed as the public summary.
//   v3/tampered-approve-human-deploy-gate-private-repo: the projection's commit
//      SHA edited after signing, hash recomputed: fails at the signature.
//   v3/outside-allowlist-approve-human-execute-lane-refund: validly signed with
//      the test key over a projection that also carries action.parameters,
//      which no issuer may publish: a verifier rejects it (PROJECTION_NOT_ALLOWED).
//   v3/openings/: the private side, which only test vectors publish: each
//      committed request as its exact text, and openings.json, the commitment
//      openings with their salts and expected results.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { attestationBytes, canonicalBytes, outputHash, requestCommitment, signingDigest } from "./canonicalize.mjs";
import { PROJECTION_TAG_BY_LANE, buildPublicProjection } from "./public-projection.mjs";

const root = new URL("..", import.meta.url).pathname;
const check = process.argv.includes("--check");

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
// Receipt format v3 (jcs_v3): SPEC.md sections 3.4 to 3.7 and 6.7.
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

/**
 * Deploy-gate lane under v3: buildDeployGateReceiptRequestJson (app
 * receipt-payload.ts) with scope.visibility recorded, then
 * bindDeployGatePolicy's authorizationBinding (app authorization-binding.ts)
 * and, for a multi-approver rule, the approve route's policyAuthorization,
 * stored as canonical text (requestJsonForReceiptSigning). Finding excerpts
 * are already null, as the builder strips them.
 */
function deployGateRequestJsonV3({ requestId, expiresAtIso, scope, policyDecision, authorizationBinding, policyAuthorization, enrichmentSnapshot }) {
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
      visibility: scope.visibility,
    },
    metadata: { deployGateRequestId: requestId },
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
  requestJson: v3PrivateRequestJson, // stored, not signed: committed
  lane: "deploy_gate",
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
      { userId: "user:usr_vec_bob_00000002", displayName: "bob-example", authMethod: "session_stepup_webauthn", at: "2026-10-06T10:30:00.000Z" },
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
  agentId: "github-actions",
  runId: "run_18533987102",
  status: "APPROVED",
  riskTier: null,
  policyVersion: "deploy-gate-v1",
  reasonCodes: JSON.stringify(["DEPLOY_GATE_APPROVED"]),
  summary: "Deploy gate authorization approved",
  deciderId: "user:usr_vec_bob_00000002",
  deciderDisplay: "bob-example",
  deciderAuthMethod: "session_stepup_webauthn",
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
// (app revoke route): the scope is copied from the revoked receipt's request,
// visibility included. deciderDisplay is the revoker's internal user id, as
// the route at app commit c655e8d5 signs it (later builds sign the GitHub
// handle when the user has one; the format is the same either way).
const v3RevokeReason = "Migration window moved to Thursday; withdrawn until then";
const v3RevokeRequestJson = canonicalJson({
  intent: { name: "authorization_revocation", summary: "Authorization withdrawn" },
  metadata: { revokedReceiptId: v3ApprovePrivate.id, deployGateRequestId: v3PrivateRequestId, reason: v3RevokeReason },
  scope: JSON.parse(v3PrivateRequestJson).scope,
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

/** Commit to the row's request and project it under its lane's tag, as the issuer's signer does. */
function bindV3(row, name, override = {}) {
  const salt = v3Salt(name);
  return {
    ...row,
    requestCommitment: requestCommitment(salt, row.requestJson),
    publicProjectionJson: override.publicProjectionJson ?? buildPublicProjection(PROJECTION_TAG_BY_LANE[row.lane], row.requestJson),
    salt,
  };
}

const V3_HINT =
  "Verify SHA-256(payload_bytes) equals signed_payload_hash, re-canonicalize the payload under jcs_v3, verify the Ed25519 signature over the digest with the public key for key_id, then check that publicProjectionJson is within its tag's allowlist (SPEC.md section 6.7). The request holder also opens requestCommitment with the request text and salt.";

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
const v3LeakProjection = JSON.parse(buildPublicProjection("execute/v1", v3RefundRequestJson));
v3LeakProjection.action.parameters = v3RefundRequest.action.parameters;
const v3LeakBound = bindV3({ ...v3ApproveRefund, id: "cmvec10v3leakedparams00000001" }, v3LeakName, {
  publicProjectionJson: canonicalJson(v3LeakProjection),
});

const v3Vectors = {
  "approve-human-deploy-gate-private-repo.json": v3Envelope(v3PrivateBound, {
    description: "jcs_v3. APPROVED by a named human (passkey step-up) on the deploy-gate lane for a private repository. The signed bytes carry no companyId, idemKey, requestJson or inputHash: a salted requestCommitment and a deploy_gate/v1 projection instead. scope.visibility is private, so the projection omits every repository-identity (†) path: no repository, ref, workflow, branches, changed paths or PR number. The commit SHA, environment, capability and rule@version stay public. The committed request is test-vectors/v3/openings/approve-human-deploy-gate-private-repo.request.json.",
    source: "app src/app/api/v1/deploy-requests/[requestId]/approve/route.ts with PP_RECEIPT_V3=on; signing/public-projection.ts, signing/request-commitment.ts",
    expected: "verified",
  }),
  "approve-human-deploy-gate-public-repo.json": v3Envelope(v3PublicBound, {
    description: "jcs_v3. APPROVED by the second of two required approvers on the deploy-gate lane for a public repository. scope.visibility is public, so the projection carries the repository-identity (†) paths. The recorded decisions are projected as display name, auth method and time only; user ids, the rule's rationale, approver lists and the enrichment stay behind the commitment.",
    source: "app src/app/api/v1/deploy-requests/[requestId]/approve/route.ts (multi-approver rule) with PP_RECEIPT_V3=on",
    expected: "verified",
  }),
  "approve-human-execute-lane-refund.json": v3Envelope(v3RefundBound, {
    description: "jcs_v3. APPROVED by a named human on the execute lane, signed at the decision before the action ran. The execute/v1 projection carries the intent and action names and the two context enums; the tenant, the parameters, the agent's summary and the context metadata stay behind the commitment.",
    source: "app src/lib/permission-router/receipt-signing.ts with PP_RECEIPT_V3=on",
    expected: "verified",
  }),
  "revoke-human-deploy-gate.json": v3Envelope(v3RevokeBound, {
    description: "jcs_v3. The private-repository approval above, revoked: the revocation lane, DENIED, resolutionType deny. The revocation/v1 projection links the revoked receipt and request and copies the revoked request's scope under the same visibility rule. The reason is free text: it is the signed, public summary and is never projected.",
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
};

// The private side. A real issuer never publishes it; it hands a request and
// its salt to the workspace that owns the receipt.
const reformattedPrivateRequest = JSON.stringify(JSON.parse(v3PrivateRequestJson), null, 2);
const modifiedRefundRequest = v3RefundRequestJson.replace('"amountCents":480000', '"amountCents":480001');
if (modifiedRefundRequest === v3RefundRequestJson) throw new Error("modified refund request did not change");

const opening = (receiptVector, requestFile, salt, expected, note) => ({
  receipt_vector: receiptVector,
  request_file: requestFile,
  salt_hex: salt.toString("hex"),
  expected,
  note,
});
const v3Openings = {
  "approve-human-deploy-gate-private-repo.request.json": new ExactText(v3PrivateRequestJson),
  "approve-human-deploy-gate-public-repo.request.json": new ExactText(v3PublicRequestJson),
  "approve-human-execute-lane-refund.request.json": new ExactText(v3RefundRequestJson),
  "revoke-human-deploy-gate.request.json": new ExactText(v3RevokeRequestJson),
  "reformatted-approve-human-deploy-gate-private-repo.request.json": new ExactText(reformattedPrivateRequest),
  "modified-approve-human-execute-lane-refund.request.json": new ExactText(modifiedRefundRequest),
  "openings.json": {
    description:
      "Commitment openings for the jcs_v3 vectors (SPEC.md section 6.7, step 2). Each case names a receipt vector in test-vectors/v3/, a request file in this directory (its exact text: the commitment covers it byte for byte, so read it without reformatting) and a 32-byte salt in hex. expected is the result of the opening step alone: opened, REQUEST_COMMITMENT_MISMATCH or PUBLIC_PROJECTION_MISMATCH. These salts are fixed test values; an issuer draws 32 random bytes per receipt and never publishes them.",
    generated_by: "node tools/generate-vectors.mjs",
    cases: [
      opening("approve-human-deploy-gate-private-repo.json", "approve-human-deploy-gate-private-repo.request.json", v3PrivateBound.salt, "opened", "The committed request and its salt reproduce requestCommitment, and the deploy_gate/v1 projection rebuilt from the request equals the signed one."),
      opening("approve-human-deploy-gate-public-repo.json", "approve-human-deploy-gate-public-repo.request.json", v3PublicBound.salt, "opened", "As above, for the public repository."),
      opening("approve-human-execute-lane-refund.json", "approve-human-execute-lane-refund.request.json", v3RefundBound.salt, "opened", "As above, under execute/v1."),
      opening("revoke-human-deploy-gate.json", "revoke-human-deploy-gate.request.json", v3RevokeBound.salt, "opened", "As above, under revocation/v1."),
      opening("approve-human-deploy-gate-private-repo.json", "approve-human-deploy-gate-private-repo.request.json", v3PublicBound.salt, "REQUEST_COMMITMENT_MISMATCH", "The right request with another receipt's salt."),
      opening("approve-human-deploy-gate-private-repo.json", "reformatted-approve-human-deploy-gate-private-repo.request.json", v3PrivateBound.salt, "REQUEST_COMMITMENT_MISMATCH", "The same request object pretty-printed: the commitment covers the exact text, never a re-serialization."),
      opening("approve-human-execute-lane-refund.json", "modified-approve-human-execute-lane-refund.request.json", v3RefundBound.salt, "REQUEST_COMMITMENT_MISMATCH", "The right salt with one byte of the request changed (amountCents 480000 to 480001), a field the projection does not show."),
      opening(`${v3LeakName}.json`, "approve-human-execute-lane-refund.request.json", v3LeakBound.salt, "PUBLIC_PROJECTION_MISMATCH", "The commitment opens, but the execute/v1 projection rebuilt from the request lacks the action.parameters the defective receipt signed."),
    ],
  },
};

const allVectors = {
  ...vectors,
  ...Object.fromEntries(Object.entries(attestationVectors).map(([name, value]) => [`attestations/${name}`, value])),
  ...Object.fromEntries(Object.entries(v3Vectors).map(([name, value]) => [`v3/${name}`, value])),
  ...Object.fromEntries(Object.entries(v3Openings).map(([name, value]) => [`v3/openings/${name}`, value])),
};

let drift = 0;
if (!check) {
  mkdirSync(join(root, "test-vectors", "attestations"), { recursive: true });
  mkdirSync(join(root, "test-vectors", "v3", "openings"), { recursive: true });
}
for (const [name, value] of Object.entries(allVectors)) {
  const path = join(root, "test-vectors", name);
  // A committed request is published as its exact text: no reformatting and
  // no trailing newline, because the commitment covers it byte for byte.
  const text = value instanceof ExactText ? value.text : `${JSON.stringify(value, null, 2)}\n`;
  if (check) {
    const current = existsSync(path) ? readFileSync(path, "utf8") : null;
    if (current !== text) {
      drift += 1;
      console.error(`DRIFT ${name}: regenerate with node tools/generate-vectors.mjs`);
    }
  } else {
    writeFileSync(path, text);
    console.log(`wrote test-vectors/${name}`);
  }
}
if (check) {
  if (drift) process.exit(1);
  console.log("vectors match their generator");
}
