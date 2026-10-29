// Conformance tests for the MCP Guard local-issuer vectors (SPEC.md section 14).
//
//   node --test "test/*.test.mjs"
//
// Each vector under test-vectors/mcp-guard/ verifies with the reference
// verifier against the MCP Guard key set (never against the hosted service's),
// its key is the one its self-certifying id names and the pin in the key set,
// its payload matches schema/receipt-v2-mcp-guard.json, its requestJson is
// canonical and carries no argument, and its inputHash recomputes from the call
// published beside it. The tampered vector fails at the signature.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalBytes } from "../tools/canonicalize.mjs";
import { verifyArtifact } from "../tools/verify.mjs";
import { validate } from "./mini-schema.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (relative) => JSON.parse(readFileSync(join(root, relative), "utf8"));
const DIR = "test-vectors/mcp-guard";

const schema = read("schema/receipt-v2-mcp-guard.json");
const hostedSchema = read("schema/receipt-v2.json");
const artifactSchema = read("schema/artifact.json");
const keySet = read(`${DIR}/keys.json`);
const hostedKeys = read("test-vectors/keys.json");
const files = readdirSync(join(root, DIR)).filter((n) => n.endsWith(".json") && n !== "keys.json").sort();

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
function sortDeep(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortDeep);
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortDeep(value[key])]));
}
/** pp.hashable_payload.v1 with metadata null. */
const inputHash = ({ tool, operation, input }) =>
  `sha256:${sha256(JSON.stringify(sortDeep(JSON.parse(JSON.stringify({ tool, operation, input, metadata: null })))))}`;

test("one vector per MCP Guard signing path, a demo receipt and a tampered one", () => {
  for (const name of [
    "approve-policy-rule.json",
    "deny-policy-rule.json",
    "approve-countdown-deploy.json",
    "approve-operator-merge.json",
    "deny-operator-post.json",
    "approve-operator-webhook-merge.json",
    "deny-approval-expired.json",
    "approve-demo-operator.json",
    "tampered-relabel-countdown-deploy.json",
  ]) {
    assert.ok(files.includes(name), `missing ${name}`);
  }
});

test("every key id is the fingerprint of its key, and the published pin matches", () => {
  for (const key of keySet.keys) {
    const raw = Buffer.from(key.public_key_b64, "base64");
    assert.equal(raw.length, 32);
    const demo = key.key_id.startsWith("mcpg-demo-");
    assert.equal(key.key_id, `mcpg-${demo ? "demo-" : ""}${sha256(raw).slice(0, 16)}`);
    assert.ok(keySet.trust.includes(`${key.key_id}=sha256:${sha256(raw)}`), `no pin for ${key.key_id}`);
  }
});

for (const name of files) {
  const vector = read(`${DIR}/${name}`);

  test(`${name}: envelope matches schema/artifact.json and the bytes are canonical`, () => {
    assert.deepEqual(validate(artifactSchema, vector), []);
    const bytes = Buffer.from(vector.artifact.payload_bytes_b64, "base64");
    const payload = JSON.parse(bytes.toString("utf8"));
    assert.ok(canonicalBytes(payload, "jcs_v2").equals(bytes));
    assert.deepEqual(vector.receipt, payload, "receipt copy drifted from the signed bytes");
  });

  if (name.startsWith("tampered-")) {
    test(`${name}: verification fails at the signature`, () => {
      const result = verifyArtifact(vector, keySet);
      assert.equal(result.ok, false);
      assert.equal(result.code, "SIGNATURE_INVALID");
    });
    continue;
  }

  test(`${name}: verifies against the MCP Guard key set and matches its profile`, () => {
    const result = verifyArtifact(vector, keySet);
    assert.equal(result.ok, true, result.message);
    const payload = result.payload;
    assert.deepEqual(validate(schema, payload), [], "payload does not match schema/receipt-v2-mcp-guard.json");
    assert.ok(validate(hostedSchema, payload).length > 0, "a local receipt is not a hosted-service receipt");
    assert.equal(payload.scope, payload.signatureKeyId.startsWith("mcpg-demo-") ? "demo" : "production");
    const request = JSON.parse(payload.requestJson);
    assert.equal(payload.requestJson, JSON.stringify(sortDeep(request)), "requestJson must be canonical");
    assert.equal(request.hashes.inputHash, payload.inputHash);
    assert.equal(request.policy.decision.ruleVersion, payload.policyVersion);
    if (payload.deciderAuthMethod === "policy") {
      assert.equal(payload.deciderId, "system/mcp-guard-policy");
      assert.equal(payload.resolutionType, undefined, "policy decisions carry no resolutionType");
    } else {
      assert.equal(payload.attributionConfidence, "heuristic");
      assert.equal(payload.resolutionType, payload.status === "APPROVED" ? "allow_once" : "deny");
    }
  });

  test(`${name}: inputHash recomputes from the call, and no argument value is signed`, () => {
    assert.equal(vector.receipt.inputHash, inputHash(vector.call));
    const bytes = Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8");
    // The scope identifiers (environment, PR ref, commit) are signed on purpose; nothing else from the call is.
    const scopeText = JSON.stringify(JSON.parse(vector.receipt.requestJson).scope ?? {});
    for (const value of Object.values(vector.call.input)) {
      if (typeof value !== "string" || value.length < 4 || scopeText.includes(value)) continue;
      assert.ok(!bytes.includes(value), `argument value ${value} is in the signed bytes`);
    }
    const changed = { ...vector.call, input: { ...vector.call.input, injected: true } };
    assert.notEqual(vector.receipt.inputHash, inputHash(changed));
  });

  test(`${name}: does not verify against the hosted service's key set`, () => {
    const result = verifyArtifact(vector, hostedKeys);
    assert.equal(result.ok, false);
    assert.equal(result.code, "KEY_NOT_FOUND");
  });
}
