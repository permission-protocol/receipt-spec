// Generates the MCP Guard local-issuer test vectors under test-vectors/mcp-guard/
// (SPEC.md section 14).
//
//   node tools/generate-mcp-guard-vectors.mjs           # write the files
//   node tools/generate-mcp-guard-vectors.mjs --check   # fail if the files on disk differ
//
// MCP Guard (permission-protocol/mcp-guard, 0.3.0 and later) is a local issuer:
// an open-source MCP proxy that signs its own decisions under jcs_v2 with a key
// its operator creates (`mcp-guard keys init`). Its receipts use the same
// canonicalization, digest and signature as the hosted service, a different
// key set, and the value profile in schema/receipt-v2-mcp-guard.json.
//
// Every record below is built the way mcp-guard's issuer builds it
// (mcp-guard src/issuer.ts, Issuer.record), field for field, from fixed inputs:
// a fixed receipt id, run id, decision id and time where the issuer draws
// random ones. Each vector also publishes the call it decided (`call`: tool,
// operation, input), which the receipt itself never carries, so a verifier can
// recompute the signed inputHash (pp.hashable_payload.v1).
//
// The keys are derived from fixed seeds (SHA-256 of a label) and sign nothing
// outside this repository. Key ids follow mcp-guard's rule: "mcpg-" (or
// "mcpg-demo-" for a demo key) plus the first 16 hex digits of SHA-256 of the
// raw 32-byte public key.
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalBytes, signingDigest } from "./canonicalize.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const check = process.argv.includes("--check");
const OUT = "test-vectors/mcp-guard";

const sha256 = (data) => createHash("sha256").update(data).digest();

function keyFromSeed(label, demo) {
  const seed = sha256(label);
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  const raw = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  const keyId = `mcpg-${demo ? "demo-" : ""}${sha256(raw).toString("hex").slice(0, 16)}`;
  return { privateKey, raw, keyId, demo };
}

const PRODUCTION_KEY = keyFromSeed("receipt-spec mcp-guard test key", false);
const DEMO_KEY = keyFromSeed("receipt-spec mcp-guard demo test key", true);

// ---------------------------------------------------------------------------
// mcp-guard's issuer, transcribed (src/issuer.ts at 0.3.0).
// ---------------------------------------------------------------------------

function sortKeysDeep(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  const sorted = {};
  for (const key of Object.keys(value).sort()) sorted[key] = sortKeysDeep(value[key]);
  return sorted;
}
const canonicalJsonText = (value) => JSON.stringify(sortKeysDeep(value));

/** pp.hashable_payload.v1 with metadata null, as mcp-guard computes it. */
export function mcpGuardInputHash(tool, operation, input) {
  const normalized = JSON.parse(JSON.stringify({ tool, operation, input, metadata: null }));
  return `sha256:${sha256(canonicalJsonText(normalized)).toString("hex")}`;
}

function classifyRisk(label, argKeys) {
  const text = `${label} ${argKeys.join(" ")}`.toLowerCase();
  if (/(delete|destroy|drop|truncate|wipe|remove)/.test(text)) return "critical";
  if (/(prod|deploy|release|publish|billing|payment|spend|merge|migrat|auth|admin|secret|token|password|key)/.test(text)) return "high";
  if (/(write|update|create|patch|modify|sync|email|post|notify)/.test(text)) return "medium";
  return "low";
}

function deciderFields(decider, status) {
  if (decider.kind === "policy") {
    return { deciderId: "system/mcp-guard-policy", deciderDisplay: "mcp-guard policy", deciderAuthMethod: "policy", attributionConfidence: "credentialed" };
  }
  return {
    deciderId: `local:${decider.operator}`,
    deciderDisplay: decider.operator,
    deciderAuthMethod: "local_console",
    attributionConfidence: "heuristic",
    resolutionType: status === "APPROVED" ? "allow_once" : "deny",
  };
}

// The policy every vector was decided under; its SHA-256 is the signed policyVersion.
const POLICY = `default_action: block
server_label: infra-mcp
rules:
  - { id: echo, tool: echo, action: allow }
  - { id: nope, tool: delete_records, action: block }
  - { id: deploy, tool: deploy, action: require_approval, reversibility: reversible, countdown_seconds: 300 }
  - { id: merge, tool: merge_pr, action: require_approval, reversibility: irreversible }
  - { id: post, tool: post_x, action: require_approval, reversibility: irreversible }
  - { id: email, tool: send_email, action: require_approval, reversibility: irreversible }
`;
const POLICY_VERSION = `mcp-guard-config:sha256:${sha256(POLICY).toString("hex")}`;
const RECEIPT_TTL = 3600;
const SCOPED_RECEIPT_TTL = 900;

function record(c, key) {
  const now = new Date(c.at);
  const label = c.tool ?? c.method;
  const inputHash = mcpGuardInputHash(label, c.method, c.input);
  const decider = deciderFields(c.decider, c.status);
  const scoped = !!c.scope;
  const request = {
    action: { operation: c.method, resource: c.resource ?? "infra-mcp", ...(c.tool ? { tool: c.tool } : {}) },
    context: {
      mode: "enforce",
      ...(c.reversibility ? { reversibility: c.reversibility.toUpperCase() } : {}),
      transport: c.resource ? "webhook" : "stdio",
    },
    hashes: { inputHash },
    intent: { category: "mcp_tool_call", name: "mcp_guard_decision" },
    policy: { decision: { outcome: c.status === "APPROVED" ? "approved" : "denied", ...(c.ruleId ? { ruleId: c.ruleId } : {}), ruleVersion: POLICY_VERSION } },
    ...(scoped ? { scope: { capability: c.scope.capability, ...(c.scope.ref ? { ref: c.scope.ref } : {}), ...(c.scope.commitSha ? { commitSha: c.scope.commitSha } : {}) } } : {}),
  };
  const ttl = scoped ? SCOPED_RECEIPT_TTL : RECEIPT_TTL;
  return {
    id: `rcpt_mg_${now.getTime().toString(36)}_${c.idSuffix}`,
    idemKey: `mcp-guard:${c.decisionId}`,
    agentId: c.agentId ?? "claude-desktop",
    runId: "run_5f0c2a9e41b7d3c8",
    requestJson: canonicalJsonText(request),
    inputHash,
    status: c.status,
    riskTier: classifyRisk(label, Object.keys(c.input ?? {}).sort()),
    policyVersion: POLICY_VERSION,
    reasonCodes: JSON.stringify(c.reasonCodes),
    summary: `MCP Guard ${c.status === "APPROVED" ? "approved" : "denied"} "${label}"${decider.deciderDisplay ? ` by ${decider.deciderDisplay}` : ""}`,
    receiptVersion: 2,
    canonicalization: "jcs_v2",
    signatureAlg: "ed25519",
    signatureKeyId: key.keyId,
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
    createdAt: now.toISOString(),
    ...decider,
    scope: key.demo ? "demo" : "production",
  };
}

function artifactFor(payload, key) {
  const bytes = canonicalBytes(payload, "jcs_v2");
  const digest = signingDigest(bytes);
  return {
    receipt_id: payload.id,
    status: payload.status,
    receipt_version: 2,
    canonicalization: "jcs_v2",
    key_id: key.keyId,
    alg: "ed25519",
    signed_payload_hash: digest.toString("hex"),
    signature_b64: sign(null, digest, key.privateKey).toString("base64"),
    payload_bytes_b64: bytes.toString("base64"),
    issued_at: payload.createdAt,
    expires_at: payload.expiresAt,
  };
}

// ---------------------------------------------------------------------------
// The vectors: one per signing path of mcp-guard 0.3.0, a demo-key receipt,
// and one tampered receipt.
// ---------------------------------------------------------------------------

const CASES = {
  "approve-policy-rule.json": {
    description: "APPROVED by policy: a tools/call allowed by a rule. deciderId system/mcp-guard-policy, deciderAuthMethod policy, no resolutionType: no person decided.",
    mirrors: "mcp-guard src/proxy.ts gate() (allowed), src/issuer.ts",
    at: "2026-10-29T15:00:00.000Z", idSuffix: "0a1b2c3d4e5f", decisionId: "8a2f4c1e-0b6d-4e3a-9c57-1d2e3f405162",
    method: "tools/call", tool: "echo", input: { message: "hello" },
    status: "APPROVED", ruleId: "echo", reasonCodes: ["RULE_MATCHED:echo"], decider: { kind: "policy" },
  },
  "deny-policy-rule.json": {
    description: "DENIED by policy: a tools/call blocked by a rule. Denials are signed with the same ceremony; the arguments are bound only by inputHash.",
    mirrors: "mcp-guard src/proxy.ts gate() (blocked), src/issuer.ts",
    at: "2026-10-29T15:01:00.000Z", idSuffix: "1b2c3d4e5f60", decisionId: "9b3e5d2f-1c7e-4f4b-8d68-2e3f40516273",
    method: "tools/call", tool: "delete_records", input: { table: "customers", where: "1=1" },
    status: "DENIED", ruleId: "nope", reasonCodes: ["RULE_MATCHED:nope"], decider: { kind: "policy" },
  },
  "approve-countdown-deploy.json": {
    description: "APPROVED when a reversible hold's countdown ran out with nobody holding it. Signed as policy (COUNTDOWN_AUTO_RELEASE), never as a person, so a gate that requires a person refuses it. Scoped: deploy:production at a commit.",
    mirrors: "mcp-guard src/proxy.ts setAutoReleaseHandler, src/release.ts signHeld",
    at: "2026-10-29T15:05:00.000Z", idSuffix: "2c3d4e5f6071", decisionId: "0c4f6e30-2d8f-405c-9e79-3f405162738a",
    method: "tools/call", tool: "deploy", input: { env: "production", sha: "4f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6" }, reversibility: "reversible",
    scope: { capability: "deploy:production", commitSha: "4f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6" },
    status: "APPROVED", ruleId: "deploy", reasonCodes: ["RULE_MATCHED:deploy", "COUNTDOWN_AUTO_RELEASE"], decider: { kind: "policy" },
  },
  "approve-operator-merge.json": {
    description: "APPROVED by the operator in the local console: a held merge_pr released by local:rod. deciderAuthMethod local_console, attributionConfidence heuristic: the console token proves access to the guard's terminal; the name is configured (--operator), not authenticated. Scoped: github:merge at the PR head commit.",
    mirrors: "mcp-guard src/approval-server.ts (approve), src/release.ts signHeld",
    at: "2026-10-29T15:10:00.000Z", idSuffix: "3d4e5f607182", decisionId: "1d507f41-3e90-416d-8f8a-405162738a9b",
    method: "tools/call", tool: "merge_pr", input: { repo: "acme/api", pr_number: 16, head_sha: "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a291807" }, reversibility: "irreversible",
    scope: { capability: "github:merge", ref: "refs/pull/16/merge", commitSha: "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a291807" },
    status: "APPROVED", ruleId: "merge", reasonCodes: ["RULE_MATCHED:merge", "OPERATOR_APPROVED"], decider: { kind: "operator", operator: "rod" },
  },
  "deny-operator-post.json": {
    description: "DENIED by the operator in the local console: a held post_x refused by local:rod, resolutionType deny.",
    mirrors: "mcp-guard src/approval-server.ts (deny), src/release.ts signHeld",
    at: "2026-10-29T15:12:00.000Z", idSuffix: "4e5f60718293", decisionId: "2e618052-4fa1-427e-905b-5162738a9bac",
    method: "tools/call", tool: "post_x", input: { text: "launching tomorrow" }, reversibility: "irreversible",
    status: "DENIED", ruleId: "post", reasonCodes: ["RULE_MATCHED:post", "OPERATOR_DENIED"], decider: { kind: "operator", operator: "rod" },
  },
  "approve-operator-webhook-merge.json": {
    description: "APPROVED by the operator for a pull request queued by the GitHub webhook (no MCP call behind it): operation github/merge, resource github-webhook, transport webhook. Binds the PR head commit, not the merge commit.",
    mirrors: "mcp-guard src/approval-server.ts handleWebhook and approve, src/release.ts signHeld",
    at: "2026-10-29T15:15:00.000Z", idSuffix: "5f60718293a4", decisionId: "3f7291a3-50b2-438f-a1ac-62738a9bacbd",
    method: "github/merge", tool: "merge_pr", resource: "github-webhook", agentId: "github-webhook",
    input: { repo: "acme/api", pr_number: 21, scope_sha: "0123456789abcdef0123456789abcdef01234567" }, reversibility: "reversible",
    scope: { capability: "github:merge", ref: "refs/pull/21/merge", commitSha: "0123456789abcdef0123456789abcdef01234567" },
    status: "APPROVED", ruleId: "pr-needs-authority", reasonCodes: ["RULE_MATCHED:pr-needs-authority", "OPERATOR_APPROVED"], decider: { kind: "operator", operator: "rod" },
  },
  "deny-approval-expired.json": {
    description: "DENIED because a held call expired with no decision (APPROVAL_EXPIRED). Signed as policy: nobody decided.",
    mirrors: "mcp-guard src/proxy.ts setExpireHandler, src/release.ts signHeld",
    at: "2026-10-29T15:30:00.000Z", idSuffix: "60718293a4b5", decisionId: "40839b4b-61c3-4490-b2bd-738a9bacbdce",
    method: "tools/call", tool: "merge_pr", input: { repo: "acme/api", pr_number: 17, head_sha: "1111111111111111111111111111111111111111" }, reversibility: "irreversible",
    scope: { capability: "github:merge", ref: "refs/pull/17/merge", commitSha: "1111111111111111111111111111111111111111" },
    status: "DENIED", ruleId: "merge", reasonCodes: ["RULE_MATCHED:merge", "APPROVAL_EXPIRED"], decider: { kind: "policy" },
  },
  "approve-demo-operator.json": {
    key: DEMO_KEY,
    description: "APPROVED in a demo run (`mcp-guard demo` and the demo scripts): signed by a demo key (mcpg-demo-…), scope demo. Authorizes nothing real; gates refuse it.",
    mirrors: "mcp-guard example/test.sh, scripts/demo-keys.mjs, src/issuer.ts",
    at: "2026-10-29T15:40:00.000Z", idSuffix: "718293a4b5c6", decisionId: "5194ac5c-72d4-45a1-83ce-8a9bacbdcedf",
    method: "tools/call", tool: "send_email", input: { to: "demo@example.com", body: "hello" }, reversibility: "irreversible",
    status: "APPROVED", ruleId: "email", reasonCodes: ["RULE_MATCHED:email", "OPERATOR_APPROVED"], decider: { kind: "operator", operator: "demo" },
  },
};

const vectors = {};
for (const [name, c] of Object.entries(CASES)) {
  const key = c.key ?? PRODUCTION_KEY;
  const payload = record(c, key);
  vectors[name] = {
    description: c.description,
    generated_by: "node tools/generate-mcp-guard-vectors.mjs",
    mirrors: c.mirrors,
    artifact: artifactFor(payload, key),
    keys_url: `${OUT}/keys.json`,
    verification_hint: "Verify against test-vectors/mcp-guard/keys.json pinned by fingerprint (--trust KEY_ID=sha256:<hex>). The receipt carries no arguments: recompute inputHash from `call` with pp.hashable_payload.v1 (metadata null).",
    call: { tool: c.tool ?? c.method, operation: c.method, input: c.input },
    receipt: payload,
  };
}

// The countdown release relabelled as a person's approval after signing (the
// first attack in the F-10 design note): every decider field edited, bytes
// re-encoded, hash recomputed. Only the signature can catch it.
{
  const source = vectors["approve-countdown-deploy.json"];
  const forged = { ...source.receipt, deciderId: "local:rod", deciderDisplay: "rod", deciderAuthMethod: "local_console", attributionConfidence: "heuristic", resolutionType: "allow_once" };
  const bytes = canonicalBytes(forged, "jcs_v2");
  vectors["tampered-relabel-countdown-deploy.json"] = {
    ...source,
    description: "approve-countdown-deploy with its policy decider relabelled as the operator after signing, bytes re-encoded and the hash recomputed. Fails at the signature.",
    artifact: { ...source.artifact, signed_payload_hash: signingDigest(bytes).toString("hex"), payload_bytes_b64: bytes.toString("base64") },
    receipt: forged,
  };
}

const keySet = {
  description: "Key set for the MCP Guard vectors, in the shape `mcp-guard keys init` writes (issuer local:mcp-guard). Test keys derived from fixed seeds; they sign nothing outside this repository. `trust` lists the --trust value for each key (KEY_ID=sha256:<SHA-256 of the raw 32-byte key>); it is not part of the key-set shape.",
  issuer: "local:mcp-guard",
  keys: [PRODUCTION_KEY, DEMO_KEY].map((k) => ({
    key_id: k.keyId,
    alg: "ed25519",
    public_key_b64: k.raw.toString("base64"),
    status: "active",
    created_at: "2026-10-29T00:00:00.000Z",
    revoked_at: null,
  })),
  trust: [PRODUCTION_KEY, DEMO_KEY].map((k) => `${k.keyId}=sha256:${sha256(k.raw).toString("hex")}`),
};

const outputs = [
  ...Object.entries(vectors).map(([name, value]) => [`${OUT}/${name}`, `${JSON.stringify(value, null, 2)}\n`]),
  [`${OUT}/keys.json`, `${JSON.stringify(keySet, null, 2)}\n`],
];

let drift = 0;
if (!check) mkdirSync(join(root, OUT), { recursive: true });
for (const [relative, text] of outputs) {
  const path = join(root, relative);
  if (check) {
    const current = existsSync(path) ? readFileSync(path, "utf8") : null;
    if (current !== text) {
      drift += 1;
      console.error(`DRIFT ${relative}: regenerate with node tools/generate-mcp-guard-vectors.mjs`);
    }
  } else {
    writeFileSync(path, text);
    console.log(`wrote ${relative}`);
  }
}
if (check) {
  if (drift) process.exit(1);
  console.log("mcp-guard vectors match their generator");
}
