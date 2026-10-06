// Conformance tests for receipt format v3, jcs_v3 (SPEC.md sections 3.4 to
// 3.7 and 6.7).
//
//   node --test "test/*.test.mjs"
//
// Every vector under test-vectors/v3/ states its expected result. A verified
// one must: validate as an envelope, re-canonicalize to its exact signed bytes
// under jcs_v3, verify its Ed25519 signature against the key set, pass the
// projection check, validate against schema/receipt-v3.json, and carry none of
// the fields jcs_v3 dropped or any private value of its request. The tampered
// one must fail at the signature; the outside-allowlist one must verify its
// signature and fail the projection check. test-vectors/v3/openings/ holds
// the commitment openings with their expected results.
import assert from "node:assert/strict";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { SIGNED_FIELDS_V3, canonicalBytes, canonicalize, requestCommitment, signingDigest } from "../tools/canonicalize.mjs";
import {
  PROJECTION_ALLOWLISTS,
  PROJECTION_TAG_BY_LANE,
  buildPublicProjection,
  checkPublicProjection,
  projectionProblem,
} from "../tools/public-projection.mjs";
import { openRequestCommitment, verifyArtifact } from "../tools/verify.mjs";
import { validate } from "./mini-schema.mjs";

const root = new URL("..", import.meta.url).pathname;
const read = (relative) => JSON.parse(readFileSync(join(root, relative), "utf8"));
const readText = (relative) => readFileSync(join(root, relative), "utf8");

const schema = read("schema/receipt-v3.json");
const artifactSchema = read("schema/artifact.json");
const keys = read("test-vectors/keys.json");
const openings = read("test-vectors/v3/openings/openings.json").cases;
const files = readdirSync(join(root, "test-vectors", "v3")).filter((name) => name.endsWith(".json")).sort();
const testKey = createPrivateKey(readFileSync(join(root, "fixtures/keypair-test/private-key.pem")));

const decode = (vector) => JSON.parse(Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8"));
const sortDeep = (value) =>
  value === null || typeof value !== "object"
    ? value
    : Array.isArray(value)
      ? value.map(sortDeep)
      : Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortDeep(value[key])]));

/** An envelope signed for real with the repository's test key, for negative cases built in a test. */
function signedEnvelope(payload) {
  const bytes = Buffer.from(JSON.stringify(sortDeep(payload)), "utf8");
  const digest = signingDigest(bytes);
  return {
    artifact: {
      receipt_id: payload.id,
      key_id: payload.signatureKeyId,
      alg: "ed25519",
      signed_payload_hash: digest.toString("hex"),
      signature_b64: sign(null, digest, testKey).toString("base64"),
      payload_bytes_b64: bytes.toString("base64"),
    },
  };
}

test("the v3 vector set: every lane, both repository visibilities, a tampered and an outside-allowlist vector", () => {
  const verified = files.filter((name) => read(`test-vectors/v3/${name}`).expected === "verified");
  const tags = verified.map((name) => read(`test-vectors/v3/${name}`).projection.projection).sort();
  assert.deepEqual([...new Set(tags)], ["deploy_gate/v1", "execute/v1", "revocation/v1"]);
  const visibilities = verified.map((name) => read(`test-vectors/v3/${name}`).projection.scope?.visibility).filter(Boolean);
  assert.ok(visibilities.includes("public") && visibilities.includes("private"));
  assert.deepEqual(
    files.map((name) => read(`test-vectors/v3/${name}`).expected).filter((expected) => expected !== "verified").sort(),
    ["PROJECTION_NOT_ALLOWED", "SIGNATURE_INVALID"]
  );
});

for (const name of files) {
  const vector = read(`test-vectors/v3/${name}`);

  test(`v3/${name}: envelope matches schema/artifact.json`, () => {
    assert.deepEqual(validate(artifactSchema, vector), []);
    assert.equal(vector.artifact.receipt_version, 3);
    assert.equal(vector.artifact.canonicalization, "jcs_v3");
  });

  test(`v3/${name}: payload bytes are the jcs_v3 encoding of the payload`, () => {
    const bytes = Buffer.from(vector.artifact.payload_bytes_b64, "base64");
    const payload = JSON.parse(bytes.toString("utf8"));
    assert.equal(payload.canonicalization, "jcs_v3");
    assert.ok(canonicalBytes(payload, "jcs_v3").equals(bytes));
    assert.deepEqual(vector.receipt, payload, "receipt copy drifted from the signed bytes");
    assert.deepEqual(vector.projection, JSON.parse(payload.publicProjectionJson), "projection copy drifted from the signed bytes");
  });

  if (vector.expected === "SIGNATURE_INVALID") {
    test(`v3/${name}: verification fails at the signature`, () => {
      const result = verifyArtifact(vector, keys);
      assert.equal(result.ok, false);
      assert.equal(result.code, "SIGNATURE_INVALID");
      assert.equal(result.exitCode, 1);
    });
    continue;
  }

  if (vector.expected === "PROJECTION_NOT_ALLOWED") {
    test(`v3/${name}: the signature verifies, and the projection check rejects it as a policy failure`, () => {
      const result = verifyArtifact(vector, keys);
      assert.equal(result.ok, false);
      assert.equal(result.code, "PROJECTION_NOT_ALLOWED");
      assert.equal(result.exitCode, 9);
      // Everything outside the projection is a well-formed v3 payload: the defect is the projection alone.
      assert.deepEqual(validate(schema, decode(vector)), []);
    });
    continue;
  }

  assert.equal(vector.expected, "verified", `v3/${name}: unknown expected result ${vector.expected}`);
  test(`v3/${name}: verifies, passes the projection check, and matches schema/receipt-v3.json`, () => {
    const result = verifyArtifact(vector, keys);
    assert.equal(result.ok, true, result.message);
    assert.equal(result.projectionTag, vector.projection.projection);
    assert.equal(result.commitmentOpened, false);
    assert.deepEqual(validate(schema, result.payload), []);
    assert.equal(result.payload.id, vector.artifact.receipt_id);
    if (result.payload.reasonCodes !== undefined) {
      const codes = JSON.parse(result.payload.reasonCodes);
      assert.ok(Array.isArray(codes) && codes.every((code) => typeof code === "string"));
    }
  });

  test(`v3/${name}: the signed bytes carry only jcs_v3 fields, none of the dropped ones, and nothing private`, () => {
    const text = Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8");
    const payload = JSON.parse(text);
    assert.deepEqual(Object.keys(payload).filter((key) => !SIGNED_FIELDS_V3.includes(key)), []);
    for (const dropped of ["companyId", "idemKey", "requestJson", "inputHash", "requestCommitmentSalt"]) {
      assert.equal(payload[dropped], undefined, `${dropped} must not be signed under jcs_v3`);
    }
    const opening = openings.find((entry) => entry.receipt_vector === name && entry.expected === "opened");
    const request = JSON.parse(readText(`test-vectors/v3/openings/${opening.request_file}`));
    const salt = Buffer.from(opening.salt_hex, "hex");
    assert.ok(!text.includes(opening.salt_hex) && !text.includes(salt.toString("base64")), "the salt never appears in the bytes");
    assert.ok(!text.includes(request.tenantId ?? "co_vector_tenant_0001"), "the tenant never appears in the bytes");
    // Every string the request holds outside the projection's allowlist must be
    // absent from the bytes, unless the receipt publishes it in its own right
    // (inside a projected value or a signed top-level field).
    const published = [...stringLeaves(vector.projection), ...Object.values(payload).filter((value) => typeof value === "string" && !value.startsWith("{"))];
    const leaked = stringLeaves(request).filter((value) => value.length >= 6 && !published.some((shown) => shown.includes(value)) && text.includes(value));
    assert.deepEqual(leaked, [], `private request values in the signed bytes: ${leaked.join(", ")}`);
  });
}

function stringLeaves(value) {
  if (typeof value === "string") return [value];
  if (value === null || typeof value !== "object") return [];
  return Object.values(value).flatMap(stringLeaves);
}

test("v3 private-repository vector: no repository identity, while commit, environment and rule@version stay public", () => {
  const vector = read("test-vectors/v3/approve-human-deploy-gate-private-repo.json");
  const text = Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8");
  for (const secret of ["acme/payments-core", "refs/pull/77/merge", "production-deploy.yml", "rotate_ledger_key.sql", "rotate-key.ts", "PAY-412", "Rotates the ledger"]) {
    assert.ok(!text.includes(secret), `the private repository's ${secret} is in the signed bytes`);
  }
  assert.equal(vector.projection.scope.visibility, "private");
  assert.equal(vector.projection.scope.commitSha, "3c9e1f0a7b2d4c6e8f0a1b3c5d7e9f1a2b4c6d8e");
  assert.equal(vector.projection.policy.decision.ruleId, "hold.protected_path");
  assert.equal(vector.projection.policy.authorizationBinding.repository, undefined);
});

test("v3 public-repository vector: repository identity present, recorded decisions without user ids", () => {
  const vector = read("test-vectors/v3/approve-human-deploy-gate-public-repo.json");
  const { projection } = vector;
  assert.equal(projection.scope.repo, "acme/open-sdk");
  assert.equal(projection.scope.ref, "refs/pull/1204/merge");
  assert.equal(projection.policy.authorizationBinding.prNumber, 1204);
  assert.deepEqual(projection.policy.decision.matchedInputs.changedPaths, ["packages/sdk/package.json", "packages/sdk/src/client.ts"]);
  assert.deepEqual(projection.policyAuthorization.recordedDecisions.map((decision) => Object.keys(decision).sort()), [
    ["at", "authMethod", "displayName"],
    ["at", "authMethod", "displayName"],
  ]);
  const text = Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8");
  for (const secret of ["usr_vec_alice_00000001", "Every SDK release needs two maintainers", "Bumps the SDK", "approvalRequirements", "requirements"]) {
    assert.ok(!text.includes(secret), `${secret} is in the signed bytes`);
  }
});

test("v3 commitment openings (openings.json): each case gives its expected result", () => {
  assert.ok(openings.length >= 6);
  for (const entry of openings) {
    const vector = read(`test-vectors/v3/${entry.receipt_vector}`);
    const payload = decode(vector);
    const requestJson = readText(`test-vectors/v3/openings/${entry.request_file}`);
    const salt = Buffer.from(entry.salt_hex, "hex");
    assert.equal(salt.length, 32);
    const problem = openRequestCommitment(payload, requestJson, salt);
    assert.equal(problem ? problem.code : "opened", entry.expected, `${entry.receipt_vector} with ${entry.request_file}: ${entry.note}`);
    if (entry.expected === "opened") {
      assert.equal(requestCommitment(salt, requestJson), payload.requestCommitment);
      const result = verifyArtifact(vector, keys, { opening: { requestJson, salt } });
      assert.equal(result.ok, true, result.message);
      assert.equal(result.commitmentOpened, true);
    } else if (vector.expected === "verified") {
      const result = verifyArtifact(vector, keys, { opening: { requestJson, salt } });
      assert.equal(result.code, entry.expected);
      assert.equal(result.exitCode, 10);
    }
  }
  const expected = new Set(openings.map((entry) => entry.expected));
  for (const code of ["opened", "REQUEST_COMMITMENT_MISMATCH", "PUBLIC_PROJECTION_MISMATCH"]) assert.ok(expected.has(code), `no ${code} case`);
});

test("v3 committed requests are canonical text, and each projection rebuilds from its request", () => {
  for (const entry of openings.filter((candidate) => candidate.expected === "opened")) {
    const requestJson = readText(`test-vectors/v3/openings/${entry.request_file}`);
    assert.equal(requestJson, JSON.stringify(sortDeep(JSON.parse(requestJson))), `${entry.request_file} is not canonical`);
    const payload = decode(read(`test-vectors/v3/${entry.receipt_vector}`));
    const tag = JSON.parse(payload.publicProjectionJson).projection;
    assert.equal(buildPublicProjection(tag, requestJson), payload.publicProjectionJson);
  }
});

test("an opening is refused for a receipt that is not jcs_v3, and needs a 32-byte salt", () => {
  const v2 = read("test-vectors/approve-human-deploy-gate.json");
  const result = verifyArtifact(v2, keys, { opening: { requestJson: "{}", salt: Buffer.alloc(32) } });
  assert.equal(result.code, "OPENING_NOT_APPLICABLE");
  const entry = openings.find((candidate) => candidate.expected === "opened");
  const payload = decode(read(`test-vectors/v3/${entry.receipt_vector}`));
  const requestJson = readText(`test-vectors/v3/openings/${entry.request_file}`);
  assert.equal(openRequestCommitment(payload, requestJson, Buffer.from(entry.salt_hex, "hex").subarray(0, 31)).code, "REQUEST_COMMITMENT_MISMATCH");
  assert.equal(openRequestCommitment(payload, requestJson, null).code, "REQUEST_COMMITMENT_UNAVAILABLE");
  assert.equal(openRequestCommitment({ ...payload, requestCommitment: undefined }, requestJson, Buffer.alloc(32)).code, "REQUEST_COMMITMENT_UNAVAILABLE");
});

test("an unknown canonicalization fails closed as unsupported, never as tampered or under another list", () => {
  const payload = decode(read("test-vectors/v3/approve-human-deploy-gate-private-repo.json"));
  for (const value of ["jcs_v4", "jcs_v10", "JCS_V3", "jcs_v3 "]) {
    const result = verifyArtifact(signedEnvelope({ ...payload, canonicalization: value }), keys);
    assert.equal(result.code, "CANONICALIZATION_UNSUPPORTED", value);
    assert.equal(result.exitCode, 8);
  }
  // A jcs_v3 payload relabelled as an older version does not survive that version's field list.
  for (const value of ["jcs_v2", "jcs_v1"]) {
    const result = verifyArtifact(signedEnvelope({ ...payload, canonicalization: value }), keys);
    assert.equal(result.code, "CANONICAL_MISMATCH", value);
  }
  // No canonicalization at all is malformed, as before.
  const { canonicalization: _drop, ...unlabelled } = payload;
  assert.equal(verifyArtifact(signedEnvelope(unlabelled), keys).code, "MALFORMED");
});

test("an unknown projection tag fails closed as unsupported, even with a valid signature", () => {
  const payload = decode(read("test-vectors/v3/approve-human-execute-lane-refund.json"));
  for (const projection of ['{"projection":"execute/v2"}', '{"intent":{"name":"x"}}', "not json", '["execute/v1"]']) {
    const result = verifyArtifact(signedEnvelope({ ...payload, publicProjectionJson: projection }), keys);
    assert.equal(result.code, "PROJECTION_UNSUPPORTED", projection);
    assert.equal(result.exitCode, 8);
  }
});

test("section 6.7 step 1: the projection check accepts every build-rule output and rejects the rest", () => {
  const ok = (value) => projectionProblem(JSON.stringify(sortDeep(value)));
  // Accepted: build outputs, including aligned {} array elements and a tag with no facts.
  assert.equal(ok({ projection: "execute/v1" }), null);
  assert.equal(ok({ projection: "deploy_gate/v1", policyAuthorization: { recordedDecisions: [{ displayName: "Ada" }, {}, { at: "t" }] } }), null);
  assert.equal(ok({ projection: "deploy_gate/v1", scope: { visibility: "public", repo: "acme/app" }, metadata: { pullRequest: 42 } }), null);
  assert.equal(ok({ projection: "deploy_gate/v1", policy: { decision: { matchedInputs: { changedPaths: [] } } }, scope: { visibility: "public" } }), null);
  assert.equal(ok({ projection: "deploy_gate/v1", policy: { expiresAt: null, decision: { ruleId: 7 } } }), null);

  const rejects = [
    [{ projection: "execute/v1", action: { tool: "stripe", parameters: { amount: 1 } } }, /action\.parameters is not in the allowlist/],
    [{ projection: "execute/v1", tenantId: "co_1" }, /tenantId is not in the allowlist/],
    [{ projection: "execute/v1", intent: { name: "Email Jane Doe" } }, /identifier slot/],
    [{ projection: "execute/v1", intent: { name: "x".repeat(129) } }, /identifier slot/],
    [{ projection: "execute/v1", context: { environment: "prod" } }, /must be one of/],
    [{ projection: "deploy_gate/v1", scope: { visibility: "private", repo: "acme/app" } }, /repository identity/],
    [{ projection: "deploy_gate/v1", scope: { repo: "acme/app" } }, /repository identity/],
    [{ projection: "deploy_gate/v1", scope: { visibility: "PUBLIC" } }, /must be one of/],
    [{ projection: "deploy_gate/v1", metadata: { pullRequest: 42 } }, /repository identity/],
    [{ projection: "deploy_gate/v1", metadata: { deployGateRequestId: { nested: "x" } } }, /scalar or an array of scalars/],
    [{ projection: "deploy_gate/v1", policy: { decision: { matchedInputs: { changedPaths: [{ path: "a" }] } } }, scope: { visibility: "public" } }, /scalar or an array of scalars/],
    [{ projection: "deploy_gate/v1", policyAuthorization: { recordedDecisions: [{ userId: "u1", displayName: "Ada" }] } }, /userId is not in the allowlist/],
    [{ projection: "deploy_gate/v1", policyAuthorization: { recordedDecisions: [] } }, /non-empty array/],
    [{ projection: "deploy_gate/v1", policyAuthorization: { recordedDecisions: [{}, {}] } }, /only empty elements/],
    [{ projection: "deploy_gate/v1", policyAuthorization: { recordedDecisions: ["Ada"] } }, /must be an object/],
    [{ projection: "deploy_gate/v1", policyAuthorization: { recordedDecisions: { displayName: "Ada" } } }, /non-empty array/],
    [{ projection: "deploy_gate/v1", policy: {} }, /empty object/],
    [{ projection: "deploy_gate/v1", policy: [] }, /must be an object/],
    [{ projection: "deploy_gate/v1", enrichmentSnapshot: { summary: "x" } }, /enrichmentSnapshot is not in the allowlist/],
    [{ projection: "revocation/v1", metadata: { reason: "free text" } }, /metadata\.reason is not in the allowlist/],
  ];
  for (const [value, pattern] of rejects) assert.match(ok(value) ?? "accepted", pattern, JSON.stringify(value));

  // Not canonical text: whitespace, unsorted keys, duplicate keys.
  assert.match(projectionProblem('{"projection": "execute/v1"}'), /not canonical/);
  assert.match(projectionProblem('{"projection":"execute/v1","action":{"tool":"x"}}'), /not canonical/);
  assert.match(projectionProblem('{"intent":{"name":"a","name":"b"},"projection":"execute/v1"}'), /not canonical/);
  assert.equal(checkPublicProjection('{"projection":"deploy_gate/v9"}').code, "PROJECTION_UNSUPPORTED");
});

test("the build rule: identifier and enum slots omit, never truncate; † paths follow scope.visibility; arrays stay aligned", () => {
  const request = {
    intent: { name: "Email Jane Doe at Acme", category: "outreach", summary: "private" },
    action: { tool: "a".repeat(128), operation: "b".repeat(129), parameters: { to: "jane@example.com" } },
    context: { environment: "prod", reversibility: "IRREVERSIBLE", metadata: { x: 1 } },
  };
  assert.deepEqual(JSON.parse(buildPublicProjection("execute/v1", JSON.stringify(request))), {
    action: { tool: "a".repeat(128) },
    context: { reversibility: "IRREVERSIBLE" },
    intent: { category: "outreach" },
    projection: "execute/v1",
  });
  for (const visibility of [undefined, "private", "internal", "PUBLIC", true, { public: true }]) {
    const projection = JSON.parse(buildPublicProjection("revocation/v1", JSON.stringify({ scope: { repo: "acme/app", ref: "main", env: "production", visibility } })));
    assert.equal(projection.scope.repo, undefined, String(visibility));
    assert.equal(projection.scope.visibility, visibility === "private" ? "private" : undefined);
  }
  assert.equal(JSON.parse(buildPublicProjection("revocation/v1", JSON.stringify({ scope: { repo: "acme/app", visibility: "public" } }))).scope.repo, "acme/app");
  assert.deepEqual(
    JSON.parse(buildPublicProjection("deploy_gate/v1", JSON.stringify({ policyAuthorization: { recordedDecisions: [{ displayName: "Ada", userId: "u" }, 7, { at: "t" }] } }))).policyAuthorization,
    { recordedDecisions: [{ displayName: "Ada" }, {}, { at: "t" }] }
  );
  assert.equal(buildPublicProjection("deploy_gate/v1", '{"policy":{"decision":null},"metadata":{}}'), '{"projection":"deploy_gate/v1"}');
  for (const text of ["[]", '"text"', "null", "42", "not json", ""]) {
    assert.throws(() => buildPublicProjection("deploy_gate/v1", text), (error) => error.code === "REQUEST_NOT_OBJECT");
  }
  assert.throws(() => buildPublicProjection("deploy_gate/v2", "{}"), (error) => error.code === "PROJECTION_UNSUPPORTED");
  assert.deepEqual(PROJECTION_TAG_BY_LANE, { deploy_gate: "deploy_gate/v1", execute: "execute/v1", revocation: "revocation/v1" });
});

test("SPEC.md section 3.7 tables state exactly the allowlists tools/public-projection.mjs builds with", () => {
  const spec = readText("SPEC.md");
  for (const [tag, fields] of Object.entries(PROJECTION_ALLOWLISTS)) {
    const start = spec.indexOf(`#### \`${tag}\``);
    assert.notEqual(start, -1, `SPEC.md has no table for ${tag}`);
    const rows = [];
    for (const line of spec.slice(start).split("\n").slice(1)) {
      if (line.startsWith("#")) break;
      const match = line.match(/^\| `([^`]+)` \| ([^|]+?) \| (†?) *\|$/);
      if (match) rows.push(`${match[1]} ${match[2]}${match[3] ? " †" : ""}`);
    }
    const expected = fields.map(
      (field) =>
        `${field.path} ${field.id ? "identifier" : field.oneOf ? `one of ${field.oneOf.map((value) => `\`${value}\``).join(", ")}` : "value"}${field.repositoryIdentity ? " †" : ""}`
    );
    assert.deepEqual(rows, expected, `SPEC.md table for ${tag}`);
  }
});

test("the issuer's own golden jcs_v3 vector reproduces byte for byte", () => {
  // From permission-protocol/app tests/signing/receipt-canonicalization-golden.test.ts
  // at c655e8d5 (the issuer's v3 signer): fixed fields, the fixed salt 0..31 and
  // the golden key (32 bytes of 0x09) give these literals.
  const request = JSON.stringify({
    action: { operation: "deploy", tool: "github-actions" },
    context: { environment: "production", reversibility: "REVERSIBLE" },
    enrichmentSnapshot: { summary: "PRIVATE-ENRICHMENT" },
    intent: { category: "deployment", name: "deploy_gate_approval", summary: "Deploy gate authorization approved" },
    metadata: { deployGateRequestId: "dgr_golden" },
    policy: {
      decision: {
        matchedInputs: { analysisComplete: true, changeClass: "protected", changedPaths: ["src/private/path.ts"], defaultBranch: "main", repoPolicy: { rationale: "PRIVATE-RATIONALE" }, targetBranch: "main" },
        outcome: "approval_required",
        ruleId: "hold.protected_path",
        ruleVersion: "outcome-router-v1",
      },
      expiresAt: "2026-10-05T12:00:00.000Z",
    },
    scope: { artifact_digest: null, capability: "deploy:production", commitSha: "9f2c000000000000000000000000000000000001", env: "production", ref: "refs/heads/main", repo: "acme/private-app", visibility: "private", workflow: null },
  });
  const salt = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const projection = buildPublicProjection("deploy_gate/v1", request);
  assert.equal(
    projection,
    '{"action":{"operation":"deploy","tool":"github-actions"},"context":{"environment":"production","reversibility":"REVERSIBLE"},"intent":{"category":"deployment","name":"deploy_gate_approval"},"metadata":{"deployGateRequestId":"dgr_golden"},"policy":{"decision":{"matchedInputs":{"analysisComplete":true,"changeClass":"protected"},"outcome":"approval_required","ruleId":"hold.protected_path","ruleVersion":"outcome-router-v1"},"expiresAt":"2026-10-05T12:00:00.000Z"},"projection":"deploy_gate/v1","scope":{"capability":"deploy:production","commitSha":"9f2c000000000000000000000000000000000001","env":"production","visibility":"private"}}'
  );
  const commitment = requestCommitment(salt, request);
  assert.equal(commitment, "sha256:f9d5f7348058baf0952b8d79b8a6629831b2aa4631ab49e9360d3ae20ff909ff");
  const row = {
    id: "rcpt_dg_golden_0001", companyId: "co_golden", idemKey: "deploy-gate:dgr_golden:5d41402abc4b2a76b9719d911017c592", agentId: "github-actions", runId: "run-4242",
    requestJson: request, inputHash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", status: "APPROVED", riskTier: null, policyVersion: "deploy-gate-v1",
    reasonCodes: '["DEPLOY_GATE_APPROVED"]', summary: 'Ship it: "quoted" ünïcode — done', deciderId: "user:u_golden", deciderDisplay: "octo-signer", deciderAuthMethod: "session",
    resolutionType: "allow_once", attributionConfidence: "credentialed", scope: "production", receiptVersion: 3, canonicalization: "jcs_v3", signatureAlg: "ed25519",
    signatureKeyId: "pp_golden_k1", expiresAt: new Date("2026-10-05T12:00:00.000Z"), createdAt: new Date("2026-10-05T11:00:00.000Z"),
    requestCommitment: commitment, publicProjectionJson: projection,
  };
  const digest = createHash("sha256").update(canonicalize(row, "jcs_v3"), "utf8").digest();
  assert.equal(digest.toString("hex"), "77eba9457fc5e89a92b97b6638165c48b528c953e1ed5753d664bd42ec878c68");
  const goldenKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 9)]), format: "der", type: "pkcs8" });
  assert.equal(sign(null, digest, goldenKey).toString("base64"), "UglqMaOMGdkX/nYCXIjQYmCEPOa3uR2v84mYdepYv0QTPTbJuIKhL12wjJNkTq/IhztJ87Rl1MlDgw0UwCUDCw==");
});
