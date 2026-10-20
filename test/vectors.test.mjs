// Conformance tests for the test vectors (SPEC.md section 12).
//
//   node --test "test/*.test.mjs"
//
// Dependency-free: node:test, node:crypto, and a small JSON Schema checker that
// covers the keywords schema/receipt-v2.json uses. Every vector under
// test-vectors/ is checked the same way: the envelope validates, the payload
// re-canonicalizes to the exact signed bytes, the digest matches, the Ed25519
// signature verifies against the key set, and the decoded payload validates
// against the schema. The tampered vector must fail at the signature step.
//
// Set PP_LIVE_ARTIFACT_URL to a public artifact URL (for example
// https://app.permissionprotocol.com/r/<id>.json) to run the same checks
// against a receipt the hosted service issued, fetching its key set from the
// keys_url the artifact names. Off by default so CI stays deterministic.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { canonicalBytes } from "../tools/canonicalize.mjs";
import { verifyArtifact } from "../tools/verify.mjs";
import { validate } from "./mini-schema.mjs";

const root = new URL("..", import.meta.url).pathname;
const read = (relative) => JSON.parse(readFileSync(join(root, relative), "utf8"));

const receiptSchema = read("schema/receipt-v2.json");
const artifactSchema = read("schema/artifact.json");
const vectorKeys = read("test-vectors/keys.json");
const liveKeys = read("test-vectors/live-keys.json");

const vectorFiles = readdirSync(join(root, "test-vectors"))
  .filter((name) => name.endsWith(".json") && !name.endsWith("keys.json"))
  .sort();

function keySetFor(name) {
  return name.startsWith("live-") ? liveKeys : vectorKeys;
}

function checkPayloadShape(payload) {
  const errors = validate(receiptSchema, payload);
  assert.deepEqual(errors, [], `payload does not match schema/receipt-v2.json: ${errors.join("; ")}`);
  // Two string fields carry JSON text. The schema can only say "string"; the
  // spec says what the string must contain.
  const request = JSON.parse(payload.requestJson);
  assert.equal(typeof request, "object");
  assert.ok(request !== null && !Array.isArray(request), "requestJson must encode an object");
  assert.equal(payload.requestJson, JSON.stringify(sortDeep(request)), "requestJson must be canonical (sorted keys, no whitespace)");
  if (payload.reasonCodes !== undefined) {
    const codes = JSON.parse(payload.reasonCodes);
    assert.ok(Array.isArray(codes) && codes.every((code) => typeof code === "string"), "reasonCodes must encode an array of strings");
  }
}

function sortDeep(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortDeep);
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortDeep(value[key])]));
}

test("at least the four required vectors are present", () => {
  for (const required of [
    "approve-human-deploy-gate.json",
    "approve-policy-execute-lane.json",
    "deny-kill-switch-execute-lane.json",
    "tampered-approve-human-deploy-gate.json",
  ]) {
    assert.ok(vectorFiles.includes(required), `missing ${required}`);
  }
});

for (const name of vectorFiles) {
  const vector = read(`test-vectors/${name}`);
  const expectTampered = name.startsWith("tampered-");

  test(`${name}: envelope matches schema/artifact.json`, () => {
    assert.deepEqual(validate(artifactSchema, vector), []);
  });

  test(`${name}: payload bytes are the canonical encoding of the payload`, () => {
    const bytes = Buffer.from(vector.artifact.payload_bytes_b64, "base64");
    const payload = JSON.parse(bytes.toString("utf8"));
    assert.ok(canonicalBytes(payload, payload.canonicalization).equals(bytes));
    if (vector.receipt) {
      // The readable copy shipped next to the bytes must be the same object.
      assert.deepEqual(vector.receipt, payload, "receipt copy drifted from the signed bytes");
    }
  });

  if (expectTampered) {
    test(`${name}: verification fails at the signature`, () => {
      const result = verifyArtifact(vector, keySetFor(name));
      assert.equal(result.ok, false);
      assert.equal(result.code, "SIGNATURE_INVALID");
      assert.equal(result.exitCode, 1);
    });
  } else {
    test(`${name}: verifies against the key set and matches schema/receipt-v2.json`, () => {
      const result = verifyArtifact(vector, keySetFor(name));
      assert.equal(result.ok, true, result.message);
      checkPayloadShape(result.payload);
      assert.equal(result.payload.id, vector.artifact.receipt_id);
    });
  }
}

test("a payload whose bytes disagree with its hash is rejected before any signature work", () => {
  const vector = read("test-vectors/approve-human-deploy-gate.json");
  const broken = structuredClone(vector);
  broken.artifact.signed_payload_hash = "00".repeat(32);
  const result = verifyArtifact(broken, vectorKeys);
  assert.equal(result.ok, false);
  assert.equal(result.code, "PAYLOAD_HASH_MISMATCH");
});

test("an unknown key id fails closed", () => {
  const vector = read("test-vectors/approve-human-deploy-gate.json");
  const result = verifyArtifact(vector, { keys: [] });
  assert.equal(result.ok, false);
  assert.equal(result.code, "KEY_NOT_FOUND");
});

test("a revoked key fails closed even with a valid signature", () => {
  const vector = read("test-vectors/approve-human-deploy-gate.json");
  const revoked = structuredClone(vectorKeys);
  revoked.keys[0].status = "revoked";
  const result = verifyArtifact(vector, revoked);
  assert.equal(result.ok, false);
  assert.equal(result.code, "KEY_REVOKED");
});

test("a signed denial verifies as authentic and reads DENIED", () => {
  const vector = read("test-vectors/deny-kill-switch-execute-lane.json");
  const result = verifyArtifact(vector, vectorKeys);
  assert.equal(result.ok, true);
  assert.equal(result.decision, "DENIED");
  assert.equal(result.payload.deciderId, "system/pp-permission-router");
  assert.equal(result.payload.resolutionType, undefined, "policy decisions carry no resolutionType");
});

test(
  "live artifact from the hosted service (set PP_LIVE_ARTIFACT_URL to enable)",
  { skip: !process.env.PP_LIVE_ARTIFACT_URL },
  async () => {
    const envelope = await (await fetch(process.env.PP_LIVE_ARTIFACT_URL)).json();
    const keySet = await (await fetch(envelope.keys_url)).json();
    assert.deepEqual(validate(artifactSchema, envelope), []);
    const result = verifyArtifact(envelope, keySet);
    assert.equal(result.ok, true, result.message);
    checkPayloadShape(result.payload);
  }
);
