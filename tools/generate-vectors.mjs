// Generates the signed test vectors under test-vectors/ (SPEC.md section 11).
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
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { canonicalBytes, signingDigest } from "./canonicalize.mjs";

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

let drift = 0;
for (const [name, value] of Object.entries(vectors)) {
  const path = join(root, "test-vectors", name);
  const text = `${JSON.stringify(value, null, 2)}\n`;
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
