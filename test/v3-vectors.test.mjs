// Conformance tests for receipt format v3, jcs_v3 (SPEC.md sections 3.4 to
// 3.8 and 6.7).
//
//   node --test "test/*.test.mjs"
//
// Every vector under test-vectors/v3/ states its expected result. A verified
// one must: validate as an envelope, re-canonicalize to its exact signed bytes
// under jcs_v3, verify its Ed25519 signature against the key set, pass the
// projection check and the decider proof check, validate against
// schema/receipt-v3.json, and carry none of the fields jcs_v3 dropped (summary
// among them) or any private value of its request. The tampered one must fail
// at the signature; the outside-allowlist and decider-proof ones must verify
// their signature and fail as a policy failure; the no-binding one verifies
// for a third party and fails its opening. test-vectors/v3/openings/ holds the
// commitment openings, with the summary and binding values stated beside
// each, and their expected results.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import {
  RECEIPT_BINDING_FIELDS,
  RECEIPT_BINDING_REQUEST_KEY,
  RECEIPT_SUMMARY_REQUEST_KEY,
  RESERVED_REQUEST_KEYS,
  SIGNED_FIELDS_V3,
  canonicalBytes,
  canonicalize,
  committedRequestJson,
  receiptBindingFor,
  requestCommitment,
  signingDigest,
} from "../tools/canonicalize.mjs";
import { canonicalDeciderProofJson, checkDeciderProof, deciderProofForSigning, deciderProofFromEvidence } from "../tools/decider-proof.mjs";
import {
  PROJECTION_ALLOWLISTS,
  PROJECTION_TAG_BY_LANE,
  buildPublicProjection,
  checkPublicProjection,
  projectionProblem,
  tagWithholdsPolicyIdentity,
} from "../tools/public-projection.mjs";
import { EXIT_CODES, describeWithheldRule, openRequestCommitment, ruleOf, ruleWithheldFrom, summaryFromFile, verifyArtifact } from "../tools/verify.mjs";
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

/** An envelope signed for real with the repository's test key (or `key`), for negative cases built in a test. */
function signedEnvelope(payload, key = testKey) {
  const bytes = Buffer.from(JSON.stringify(sortDeep(payload)), "utf8");
  const digest = signingDigest(bytes);
  return {
    artifact: {
      receipt_id: payload.id,
      key_id: payload.signatureKeyId,
      alg: "ed25519",
      signed_payload_hash: digest.toString("hex"),
      signature_b64: sign(null, digest, key).toString("base64"),
      payload_bytes_b64: bytes.toString("base64"),
    },
  };
}

/** The summary an opening case states: the case's `summary` when it has one, else none stated (undefined). */
const statedSummary = (entry) => (Object.prototype.hasOwnProperty.call(entry, "summary") ? entry.summary : undefined);
/** The binding values an opening case states: the case's `binding` when it has one, else none stated (undefined). */
const statedBinding = (entry) => (Object.prototype.hasOwnProperty.call(entry, "binding") ? entry.binding : undefined);
/** The opening case whose request is this receipt's own committed request. */
const ownOpening = (name) => openings.find((entry) => entry.receipt_vector === name && entry.request_file === name.replace(/\.json$/, ".request.json"))
  ?? openings.find((entry) => entry.receipt_vector === name && entry.expected === "opened");

test("the v3 vector set: every tag, both repository visibilities, both decider proof methods, and the negative vectors", () => {
  const verified = files.filter((name) => read(`test-vectors/v3/${name}`).expected === "verified");
  const tags = verified.map((name) => read(`test-vectors/v3/${name}`).projection.projection).sort();
  assert.deepEqual([...new Set(tags)], Object.keys(PROJECTION_ALLOWLISTS).sort());
  assert.deepEqual([...new Set(tags)], ["deploy_gate/v1", "deploy_gate/v2", "execute/v1", "revocation/v1"]);
  // deploy_gate/v2 is signed for both visibilities, and for an approval and a policy denial.
  const v2 = verified.map((name) => read(`test-vectors/v3/${name}`)).filter((vector) => vector.projection.projection === "deploy_gate/v2");
  assert.deepEqual(v2.map((vector) => vector.projection.scope.visibility).sort(), ["private", "private", "public"]);
  assert.deepEqual(v2.map((vector) => vector.receipt.status).sort(), ["APPROVED", "APPROVED", "DENIED"]);
  const visibilities = verified.map((name) => read(`test-vectors/v3/${name}`).projection.scope?.visibility).filter(Boolean);
  assert.ok(visibilities.includes("public") && visibilities.includes("private"));
  const proofs = verified.map((name) => read(`test-vectors/v3/${name}`).receipt.deciderProof?.method ?? null).sort();
  assert.deepEqual([...new Set(proofs)].sort(), [null, "reauth", "webauthn"].sort());
  // One verified vector is a defect only an opening catches: no receiptBinding.
  assert.ok(verified.includes("no-binding-approve-human-execute-lane-refund.json"));
  assert.deepEqual(
    files.map((name) => read(`test-vectors/v3/${name}`).expected).filter((expected) => expected !== "verified").sort(),
    ["DECIDER_PROOF_INVALID", "DECIDER_PROOF_MISMATCH", "PROJECTION_NOT_ALLOWED", "PROJECTION_NOT_ALLOWED", "SIGNATURE_INVALID"]
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

  if (vector.expected === "DECIDER_PROOF_MISMATCH" || vector.expected === "DECIDER_PROOF_INVALID") {
    test(`v3/${name}: the signature verifies and the projection holds, and the decider proof check rejects it as a policy failure`, () => {
      const result = verifyArtifact(vector, keys);
      assert.equal(result.ok, false);
      assert.equal(result.code, vector.expected);
      assert.equal(result.exitCode, 9);
      const payload = decode(vector);
      assert.equal(checkPublicProjection(payload.publicProjectionJson).ok, true);
      assert.ok(payload.deciderProof, "the defect is in the signed deciderProof");
      if (vector.expected === "DECIDER_PROOF_MISMATCH") {
        // A well-formed proof: the schema accepts it, only the consistency rule rejects it.
        assert.deepEqual(validate(schema, payload), []);
      } else {
        // A key outside the frozen shape: the schema rejects the proof, and nothing else.
        assert.deepEqual(validate(schema, payload), ["$.deciderProof must match exactly one of 2 shapes (matches 0)"]);
      }
    });
    continue;
  }

  assert.equal(vector.expected, "verified", `v3/${name}: unknown expected result ${vector.expected}`);
  test(`v3/${name}: verifies, passes the projection and decider proof checks, and matches schema/receipt-v3.json`, () => {
    const result = verifyArtifact(vector, keys);
    assert.equal(result.ok, true, result.message);
    assert.equal(result.projectionTag, vector.projection.projection);
    assert.equal(result.commitmentOpened, false);
    assert.deepEqual(result.deciderProof, result.payload.deciderProof ?? null);
    assert.equal(checkDeciderProof(result.payload.deciderAuthMethod, result.payload.deciderProof), null);
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
    for (const dropped of ["companyId", "idemKey", "requestJson", "inputHash", "requestCommitmentSalt", "summary", "deciderProofJson"]) {
      assert.equal(payload[dropped], undefined, `${dropped} must not be signed under jcs_v3`);
    }
    const opening = ownOpening(name);
    const request = JSON.parse(readText(`test-vectors/v3/openings/${opening.request_file}`));
    // The summary is committed, never signed: it is in the request and nowhere in the bytes.
    assert.equal(typeof request[RECEIPT_SUMMARY_REQUEST_KEY], "string");
    assert.ok(!text.includes(request[RECEIPT_SUMMARY_REQUEST_KEY]), "the committed summary appears in the signed bytes");
    assert.ok(!text.includes(RECEIPT_SUMMARY_REQUEST_KEY));
    // So is the binding: its workspace, idempotency key and input hash are nowhere in the bytes.
    assert.ok(!text.includes(RECEIPT_BINDING_REQUEST_KEY));
    for (const value of Object.values(request[RECEIPT_BINDING_REQUEST_KEY] ?? {})) {
      if (value !== null) assert.ok(!text.includes(value), `the committed binding value ${value} appears in the signed bytes`);
    }
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
  // The passkey proof: the listed keys only. The stored evidence's counter,
  // bound request id and bound scope hash (an unsalted hash over the private
  // scope, which would confirm a guessed repository name) are not signed.
  assert.equal(vector.receipt.deciderAuthMethod, "session_stepup_webauthn");
  assert.deepEqual(Object.keys(vector.receipt.deciderProof).sort(), [
    "authenticatorDataHash", "challengeHash", "credentialIdHash", "method", "origin", "reviewGeneration", "rpId", "userVerified", "verifiedAt",
  ]);
  for (const unsigned of ["counter", "boundRequestId", "boundScopeHash"]) {
    assert.ok(!text.includes(`"${unsigned}"`), `${unsigned} is in the signed bytes`);
  }
  const request = JSON.parse(readText("test-vectors/v3/openings/approve-human-deploy-gate-private-repo.request.json"));
  const scopeHash = createHash("sha256")
    .update(JSON.stringify(sortDeep({ repo: request.scope.repo, env: request.scope.env, ref: request.scope.ref, commit: request.scope.commitSha, capability: request.scope.capability })), "utf8")
    .digest("hex");
  assert.ok(!text.includes(scopeHash), "the unsalted scope hash is in the signed bytes");
  assert.equal(vector.projection.scope.visibility, "private");
  assert.equal(vector.projection.scope.commitSha, "3c9e1f0a7b2d4c6e8f0a1b3c5d7e9f1a2b4c6d8e");
  assert.equal(vector.projection.policy.decision.ruleId, "hold.protected_path");
  assert.equal(vector.projection.policy.authorizationBinding.repository, undefined);
});

test("v3 public-repository vector: repository identity present, recorded decisions without user ids or auth methods, a reauth proof", () => {
  const vector = read("test-vectors/v3/approve-human-deploy-gate-public-repo.json");
  const { projection } = vector;
  assert.equal(vector.receipt.deciderAuthMethod, "session_reauth");
  assert.deepEqual(Object.keys(vector.receipt.deciderProof).sort(), ["authTime", "maxAgeMs", "method", "verifiedAt"]);
  const { authTime, maxAgeMs, verifiedAt } = vector.receipt.deciderProof;
  assert.ok(Date.parse(verifiedAt) - Date.parse(authTime) <= maxAgeMs);
  assert.equal(projection.scope.repo, "acme/open-sdk");
  assert.equal(projection.scope.ref, "refs/pull/1204/merge");
  assert.equal(projection.policy.authorizationBinding.prNumber, 1204);
  assert.deepEqual(projection.policy.decision.matchedInputs.changedPaths, ["packages/sdk/package.json", "packages/sdk/src/client.ts"]);
  // Only the final signer's step-up is signed (deciderProof), so no recorded
  // decision publishes an auth method: it would be a claim with no proof behind it.
  assert.deepEqual(projection.policyAuthorization.recordedDecisions.map((decision) => Object.keys(decision).sort()), [
    ["at", "displayName"],
    ["at", "displayName"],
  ]);
  const committedDecisions = JSON.parse(readText("test-vectors/v3/openings/approve-human-deploy-gate-public-repo.request.json")).policyAuthorization.recordedDecisions;
  assert.ok(committedDecisions.every((decision) => typeof decision.authMethod === "string"), "the committed request keeps each recorded auth method");
  const text = Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8");
  for (const secret of ["usr_vec_alice_00000001", "Every SDK release needs two maintainers", "Bumps the SDK", "approvalRequirements", "requirements", "authMethod"]) {
    assert.ok(!text.includes(secret), `${secret} is in the signed bytes`);
  }
});

test("v3 commitment openings (openings.json): each case gives its expected result", () => {
  assert.ok(openings.length >= 8);
  const tally = {};
  for (const entry of openings) {
    const vector = read(`test-vectors/v3/${entry.receipt_vector}`);
    const payload = decode(vector);
    const requestJson = readText(`test-vectors/v3/openings/${entry.request_file}`);
    const salt = Buffer.from(entry.salt_hex, "hex");
    const summary = statedSummary(entry);
    const binding = statedBinding(entry);
    assert.equal(salt.length, 32);
    const problem = openRequestCommitment(payload, requestJson, salt, { summary, binding });
    assert.equal(problem ? problem.code : "opened", entry.expected, `${entry.receipt_vector} with ${entry.request_file}: ${entry.note}`);
    tally[entry.expected] = (tally[entry.expected] ?? 0) + 1;
    if (entry.expected === "opened") {
      assert.equal(requestCommitment(salt, requestJson), payload.requestCommitment);
      const result = verifyArtifact(vector, keys, { opening: { requestJson, salt, summary, binding } });
      assert.equal(result.ok, true, result.message);
      assert.equal(result.commitmentOpened, true);
      assert.equal(result.committedSummary, JSON.parse(requestJson)[RECEIPT_SUMMARY_REQUEST_KEY] ?? null);
      if (summary !== undefined) assert.equal(result.committedSummary, summary);
      assert.deepEqual(result.committedBinding, JSON.parse(requestJson)[RECEIPT_BINDING_REQUEST_KEY]);
      if (binding !== undefined) assert.deepEqual({ ...result.committedBinding, ...binding }, result.committedBinding);
    } else if (vector.expected === "verified") {
      const result = verifyArtifact(vector, keys, { opening: { requestJson, salt, summary, binding } });
      assert.equal(result.code, entry.expected);
      assert.equal(result.exitCode, 10);
      assert.equal(EXIT_CODES[entry.expected], 10);
    }
  }
  assert.deepEqual(tally, { opened: 8, REQUEST_COMMITMENT_MISMATCH: 3, COMMITTED_SUMMARY_MISMATCH: 2, RECEIPT_BINDING_MISMATCH: 2, PUBLIC_PROJECTION_MISMATCH: 2 });
  // At least one opened case compares stated binding values, and one fails on them.
  assert.ok(openings.some((entry) => entry.expected === "opened" && entry.binding));
  assert.ok(openings.some((entry) => entry.expected === "RECEIPT_BINDING_MISMATCH" && entry.binding));
  assert.ok(openings.some((entry) => entry.expected === "RECEIPT_BINDING_MISMATCH" && !entry.binding));
});

test("v3 committed requests are canonical text that commits the binding and the summary, and each projection rebuilds from its request", () => {
  for (const entry of openings.filter((candidate) => candidate.expected === "opened")) {
    const requestJson = readText(`test-vectors/v3/openings/${entry.request_file}`);
    assert.equal(requestJson, JSON.stringify(sortDeep(JSON.parse(requestJson))), `${entry.request_file} is not canonical`);
    const vector = read(`test-vectors/v3/${entry.receipt_vector}`);
    const payload = decode(vector);
    const tag = JSON.parse(payload.publicProjectionJson).projection;
    assert.equal(buildPublicProjection(tag, requestJson), payload.publicProjectionJson);
    // The mint's rule: the request handed to it, plus the binding under
    // receiptBinding and the summary under receiptSummary.
    const { [RECEIPT_SUMMARY_REQUEST_KEY]: committed, [RECEIPT_BINDING_REQUEST_KEY]: binding, ...request } = JSON.parse(requestJson);
    assert.equal(typeof committed, "string");
    assert.deepEqual(Object.keys(binding).sort(), [...RECEIPT_BINDING_FIELDS].sort());
    // Every vector's binding is a stored row's: a workspace, and an idempotency key and input hash.
    assert.ok(Object.values(binding).every((value) => typeof value === "string" && value.length > 0), entry.request_file);
    assert.equal(committedRequestJson(JSON.stringify(request), committed, binding), requestJson);
    // The workspace never reaches the bytes; the tenant id in an execute request does not either.
    assert.ok(!Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8").includes(binding.companyId));
  }
});

test("the reserved keys: only the mint sets receiptBinding and receiptSummary, and no allowlist ever projects them", () => {
  assert.equal(RECEIPT_SUMMARY_REQUEST_KEY, "receiptSummary");
  assert.equal(RECEIPT_BINDING_REQUEST_KEY, "receiptBinding");
  assert.deepEqual([...RECEIPT_BINDING_FIELDS], ["companyId", "idemKey", "inputHash"]);
  assert.deepEqual([...RESERVED_REQUEST_KEYS].sort(), ["receiptBinding", "receiptSummary"]);
  for (const [tag, fields] of Object.entries(PROJECTION_ALLOWLISTS)) {
    for (const key of RESERVED_REQUEST_KEYS) assert.ok(fields.every((field) => field.segments[0].key !== key), `${tag} names ${key}`);
    const projected = buildPublicProjection(tag, JSON.stringify({ receiptSummary: "private reason", receiptBinding: { companyId: "co_private", idemKey: "idem-private", inputHash: "hash-private" } }));
    assert.equal(projected, JSON.stringify({ projection: tag }), tag);
  }
  const binding = { companyId: "co_1", idemKey: null, inputHash: "h" };
  const code = (fn) => {
    try {
      fn();
      return "ok";
    } catch (error) {
      return error.code;
    }
  };
  // The mint refuses a request that already carries either key, and one that is not a JSON object.
  assert.equal(code(() => committedRequestJson('{"a":1,"receiptSummary":"x"}', "y", binding)), "REQUEST_RESERVED_KEY");
  assert.equal(code(() => committedRequestJson('{"a":1,"receiptBinding":{}}', "y", binding)), "REQUEST_RESERVED_KEY");
  for (const text of ["[]", "null", '"x"', "not json", ""]) assert.equal(code(() => committedRequestJson(text, "y", binding)), "REQUEST_NOT_OBJECT", text);
  // A binding the mint would not write is refused too.
  for (const bad of [undefined, null, {}, { companyId: "c", idemKey: null }, { ...binding, extra: 1 }, { ...binding, inputHash: 7 }]) {
    assert.equal(code(() => committedRequestJson('{"a":1}', "y", bad)), "RECEIPT_BINDING_INVALID", JSON.stringify(bad));
  }
  // The mint canonicalizes the request handed to it (it need not be canonical text).
  assert.equal(committedRequestJson('{"b":1, "a":2}', null, binding), '{"a":2,"b":1,"receiptBinding":{"companyId":"co_1","idemKey":null,"inputHash":"h"}}');
  // receiptBinding always, with all three keys (null kept, never dropped); receiptSummary exactly when the summary is a string.
  assert.equal(committedRequestJson('{"a":1}', "why", binding), '{"a":1,"receiptBinding":{"companyId":"co_1","idemKey":null,"inputHash":"h"},"receiptSummary":"why"}');
  assert.equal(committedRequestJson('{"a":1}', "", binding), '{"a":1,"receiptBinding":{"companyId":"co_1","idemKey":null,"inputHash":"h"},"receiptSummary":""}');
  assert.equal(committedRequestJson('{"a":1}', null, binding), '{"a":1,"receiptBinding":{"companyId":"co_1","idemKey":null,"inputHash":"h"}}');
  assert.equal(committedRequestJson('{"a":1}', undefined, binding), '{"a":1,"receiptBinding":{"companyId":"co_1","idemKey":null,"inputHash":"h"}}');
  // A stored row's binding: its three columns, null when it has none.
  assert.deepEqual(receiptBindingFor({ companyId: "co_1", idemKey: "k", inputHash: undefined, other: 1 }), { companyId: "co_1", idemKey: "k", inputHash: null });
});

test("section 6.7 step 3: the committed binding is exactly the mint's shape, and each stated value must be the committed one", () => {
  const vector = read("test-vectors/v3/approve-human-execute-lane-refund.json");
  const base = JSON.parse(readText("test-vectors/v3/openings/approve-human-execute-lane-refund.request.json"));
  const { [RECEIPT_BINDING_REQUEST_KEY]: committedBinding, ...unbound } = base;
  const salt = Buffer.alloc(32, 7);
  /** The vector's payload, re-signed over a commitment to `requestValue`, opened with it and `binding` stated. */
  const open = (requestValue, binding) => {
    const requestJson = JSON.stringify(sortDeep(requestValue));
    const payload = { ...decode(vector), requestCommitment: requestCommitment(salt, requestJson) };
    const result = verifyArtifact(signedEnvelope(payload), keys, { opening: { requestJson, salt, binding } });
    return result.ok ? `opened:${JSON.stringify(result.committedBinding)}` : `${result.code}:${result.exitCode}`;
  };
  assert.equal(open(base, undefined), `opened:${JSON.stringify(committedBinding)}`);
  assert.equal(open(base, committedBinding), `opened:${JSON.stringify(committedBinding)}`);
  // Any subset of the three may be stated; each one stated is compared.
  for (const field of RECEIPT_BINDING_FIELDS) {
    assert.equal(open(base, { [field]: committedBinding[field] }), `opened:${JSON.stringify(committedBinding)}`, field);
    assert.equal(open(base, { [field]: `${committedBinding[field]}x` }), "RECEIPT_BINDING_MISMATCH:10", field);
    assert.equal(open(base, { [field]: null }), "RECEIPT_BINDING_MISMATCH:10", field);
  }
  assert.equal(open(base, { tenantId: committedBinding.companyId }), "RECEIPT_BINDING_MISMATCH:10");
  assert.equal(open(base, [committedBinding.companyId]), "RECEIPT_BINDING_MISMATCH:10");
  // A null value is committed as null, and only a stated null equals it.
  const nullIdem = { ...base, [RECEIPT_BINDING_REQUEST_KEY]: { ...committedBinding, idemKey: null } };
  assert.equal(open(nullIdem, { idemKey: null }), `opened:${JSON.stringify({ ...committedBinding, idemKey: null })}`);
  assert.equal(open(nullIdem, { idemKey: "" }), "RECEIPT_BINDING_MISMATCH:10");
  // Missing or malformed: the record cannot be the one the issuer committed, stated values or not.
  for (const value of [undefined, null, "co_vector_tenant_0001", [], {}, { companyId: "c", idemKey: "k" }, { ...committedBinding, tenantId: "t" }, { ...committedBinding, inputHash: 7 }, { ...committedBinding, companyId: { id: "c" } }]) {
    const request = value === undefined ? unbound : { ...unbound, [RECEIPT_BINDING_REQUEST_KEY]: value };
    assert.equal(open(request, undefined), "RECEIPT_BINDING_MISMATCH:10", JSON.stringify(value));
  }
  // A committed text that is not a JSON object carries no binding either (and is never a crash).
  for (const requestJson of ["null", "[]", '"text"', "7", "not json"]) {
    const payload = { ...decode(vector), requestCommitment: requestCommitment(salt, requestJson) };
    const result = verifyArtifact(signedEnvelope(payload), keys, { opening: { requestJson, salt } });
    assert.equal(`${result.code}:${result.exitCode}`, "RECEIPT_BINDING_MISMATCH:10", requestJson);
  }
  // The binding is checked after the summary and before the projection rebuild.
  assert.equal(open({ ...unbound, [RECEIPT_SUMMARY_REQUEST_KEY]: 7 }, undefined), "COMMITTED_SUMMARY_MISMATCH:10");
  assert.equal(open({ ...base, action: { ...base.action, tool: "github" } }, undefined), "PUBLIC_PROJECTION_MISMATCH:10");
  assert.equal(open({ ...unbound, action: { ...base.action, tool: "github" } }, undefined), "RECEIPT_BINDING_MISMATCH:10");
});

test("section 6.7 step 3: the committed summary must be text, and must be the stated one", () => {
  const vector = read("test-vectors/v3/approve-human-execute-lane-refund.json");
  const base = JSON.parse(readText("test-vectors/v3/openings/approve-human-execute-lane-refund.request.json"));
  const { [RECEIPT_SUMMARY_REQUEST_KEY]: committedText, ...request } = base;
  const salt = Buffer.alloc(32, 7);
  /** The vector's payload, re-signed over a commitment to `requestValue`, opened with it. */
  const open = (requestValue, summary) => {
    const requestJson = JSON.stringify(sortDeep(requestValue));
    const payload = { ...decode(vector), requestCommitment: requestCommitment(salt, requestJson) };
    const result = verifyArtifact(signedEnvelope(payload), keys, { opening: { requestJson, salt, summary } });
    return result.ok ? `opened:${JSON.stringify(result.committedSummary)}` : `${result.code}:${result.exitCode}`;
  };
  assert.equal(open(base, committedText), `opened:${JSON.stringify(committedText)}`);
  assert.equal(open(base, undefined), `opened:${JSON.stringify(committedText)}`);
  assert.equal(open(base, `${committedText} `), "COMMITTED_SUMMARY_MISMATCH:10");
  assert.equal(open(base, null), "COMMITTED_SUMMARY_MISMATCH:10");
  // No summary committed: none may be stated, and "none" holds.
  assert.equal(open(request, null), "opened:null");
  assert.equal(open(request, undefined), "opened:null");
  assert.equal(open(request, ""), "COMMITTED_SUMMARY_MISMATCH:10");
  // A committed summary that is not text is never one the mint wrote, stated or not.
  for (const value of [null, 7, true, { text: committedText }, [committedText]]) {
    assert.equal(open({ ...request, [RECEIPT_SUMMARY_REQUEST_KEY]: value }, undefined), "COMMITTED_SUMMARY_MISMATCH:10", JSON.stringify(value));
  }
  // An empty summary is a summary.
  assert.equal(open({ ...request, [RECEIPT_SUMMARY_REQUEST_KEY]: "" }, ""), 'opened:""');
});

test("section 6.7 step 2: the decider proof agrees with the signed auth method, both ways, and keeps its frozen shape", () => {
  const vector = read("test-vectors/v3/approve-human-execute-lane-refund.json");
  const payload = decode(vector);
  const webauthn = read("test-vectors/v3/approve-human-deploy-gate-private-repo.json").receipt.deciderProof;
  const reauth = read("test-vectors/v3/approve-human-deploy-gate-public-repo.json").receipt.deciderProof;
  const run = (deciderAuthMethod, deciderProof) => {
    const signed = { ...payload, deciderAuthMethod, deciderProof };
    if (deciderAuthMethod === undefined) delete signed.deciderAuthMethod;
    if (deciderProof === undefined) delete signed.deciderProof;
    const result = verifyArtifact(signedEnvelope(signed), keys);
    return result.ok ? "verified" : `${result.code}:${result.exitCode}`;
  };
  assert.equal(run("session_stepup_webauthn", webauthn), "verified");
  assert.equal(run("session_reauth", reauth), "verified");
  for (const method of [undefined, "session", "api_key", "anonymous_demo", "policy"]) {
    assert.equal(run(method, undefined), "verified", String(method));
    assert.equal(run(method, webauthn), "DECIDER_PROOF_MISMATCH:9", `${method} with a proof`);
    assert.equal(run(method, reauth), "DECIDER_PROOF_MISMATCH:9", `${method} with a proof`);
    // Mismatch first, whatever the proof holds.
    assert.equal(run(method, { method: "webauthn" }), "DECIDER_PROOF_MISMATCH:9");
  }
  assert.equal(run("session_stepup_webauthn", undefined), "DECIDER_PROOF_MISMATCH:9");
  assert.equal(run("session_reauth", undefined), "DECIDER_PROOF_MISMATCH:9");
  assert.equal(run("session_stepup_webauthn", reauth), "DECIDER_PROOF_MISMATCH:9");
  assert.equal(run("session_reauth", webauthn), "DECIDER_PROOF_MISMATCH:9");

  const invalid = [
    ["session_stepup_webauthn", JSON.stringify(webauthn)],
    ["session_stepup_webauthn", [webauthn]],
    ["session_stepup_webauthn", "webauthn"],
    ["session_stepup_webauthn", { ...webauthn, counter: 17 }],
    ["session_stepup_webauthn", { ...webauthn, boundScopeHash: "0".repeat(64) }],
    ["session_stepup_webauthn", { ...webauthn, credentialIdHash: webauthn.credentialIdHash.toUpperCase() }],
    ["session_stepup_webauthn", { ...webauthn, challengeHash: "abc" }],
    ["session_stepup_webauthn", { ...webauthn, userVerified: "true" }],
    ["session_stepup_webauthn", { ...webauthn, rpId: "app permissionprotocol com" }],
    ["session_stepup_webauthn", { ...webauthn, origin: `${webauthn.origin}/` }],
    ["session_stepup_webauthn", { ...webauthn, origin: "https://app.permissionprotocol.com:443" }],
    ["session_stepup_webauthn", { ...webauthn, origin: "ftp://app.permissionprotocol.com" }],
    ["session_stepup_webauthn", { ...webauthn, verifiedAt: webauthn.verifiedAt.replace(".000Z", "Z") }],
    ["session_stepup_webauthn", { ...webauthn, reviewGeneration: 0 }],
    ["session_stepup_webauthn", { ...webauthn, reviewGeneration: 1.5 }],
    ["session_stepup_webauthn", { ...webauthn, reviewGeneration: null }],
    ["session_stepup_webauthn", { ...webauthn, method: "passkey" }],
    ["session_reauth", { ...reauth, maxAgeMs: 0 }],
    ["session_reauth", { ...reauth, maxAgeMs: "300000" }],
    ["session_reauth", { ...reauth, authTime: "2026-02-30T00:00:00.000Z" }],
    ["session_reauth", { ...reauth, verifiedAt: new Date(Date.parse(reauth.authTime) + reauth.maxAgeMs + 1).toISOString() }],
    ["session_reauth", { ...reauth, extra: true }],
  ];
  for (const [method, proof] of invalid) assert.equal(run(method, proof), "DECIDER_PROOF_INVALID:9", JSON.stringify(proof));
  // Optional reviewGeneration; a re-authentication exactly maxAgeMs old; a negative age (clock skew), as the issuer's guard accepts.
  const { reviewGeneration: _round, ...withoutRound } = webauthn;
  assert.equal(run("session_stepup_webauthn", withoutRound), "verified");
  assert.equal(run("session_reauth", { ...reauth, verifiedAt: new Date(Date.parse(reauth.authTime) + reauth.maxAgeMs).toISOString() }), "verified");
  assert.equal(run("session_reauth", { ...reauth, verifiedAt: new Date(Date.parse(reauth.authTime) - 1000).toISOString() }), "verified");
});

test("the mint side: a proof is built from the stored evidence's listed keys only, and refused on any inconsistency", () => {
  const evidence = {
    method: "webauthn", credentialIdHash: "a".repeat(64), challengeHash: "b".repeat(64), authenticatorDataHash: "c".repeat(64), userVerified: false, counter: 3,
    rpId: "localhost", origin: "http://localhost:3000", boundRequestId: "dgr_1", boundScopeHash: "d".repeat(64), verifiedAt: "2026-10-06T00:00:00.000Z",
  };
  const proof = deciderProofForSigning("session_stepup_webauthn", evidence);
  assert.equal(canonicalDeciderProofJson(proof), '{"authenticatorDataHash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","challengeHash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","credentialIdHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","method":"webauthn","origin":"http://localhost:3000","rpId":"localhost","userVerified":false,"verifiedAt":"2026-10-06T00:00:00.000Z"}');
  assert.deepEqual(deciderProofFromEvidence(JSON.stringify(evidence)), proof, "stored evidence text builds the same proof");
  assert.equal(deciderProofForSigning("session", null), null);
  assert.equal(deciderProofForSigning(null, undefined), null);
  const code = (fn) => {
    try {
      fn();
      return "ok";
    } catch (error) {
      return error.code;
    }
  };
  assert.equal(code(() => deciderProofForSigning("session", evidence)), "DECIDER_PROOF_UNEXPECTED");
  assert.equal(code(() => deciderProofForSigning("session_reauth", null)), "DECIDER_PROOF_MISSING");
  assert.equal(code(() => deciderProofForSigning("session_reauth", evidence)), "DECIDER_PROOF_METHOD_MISMATCH");
  assert.equal(code(() => deciderProofForSigning("session_stepup_webauthn", "not json")), "DECIDER_PROOF_INVALID");
});

test("conformance/expected-canonical-bytes.txt lists the canonical-bytes digest of every v3 vector", () => {
  const lines = readText("conformance/expected-canonical-bytes.txt").trim().split("\n");
  const listed = new Map(lines.filter((line) => line.startsWith("test-vectors/v3/")).map((line) => line.split(" ")));
  assert.deepEqual([...listed.keys()].sort(), files.map((name) => `test-vectors/v3/${name}`).sort());
  for (const name of files) {
    const vector = read(`test-vectors/v3/${name}`);
    assert.equal(listed.get(`test-vectors/v3/${name}`), createHash("sha256").update(canonicalBytes(vector.receipt, "jcs_v3")).digest("hex"), name);
  }
  // The five v1 fixture digests RECEIPT-FORMAT-V1.md publishes stay first and unchanged.
  assert.deepEqual(lines.slice(0, 5).map((line) => line.split(" ")[0]), ["valid-deploy.json", "valid-mcp.json", "valid-payment.json", "expired.json", "tampered.json"]);
});

test("an opening is refused for a receipt that is not jcs_v3, and needs a 32-byte salt", () => {
  const v2 = read("test-vectors/approve-human-deploy-gate.json");
  const result = verifyArtifact(v2, keys, { opening: { requestJson: "{}", salt: Buffer.alloc(32) } });
  assert.equal(result.code, "OPENING_NOT_APPLICABLE");
  const entry = openings.find((candidate) => candidate.expected === "opened");
  const payload = decode(read(`test-vectors/v3/${entry.receipt_vector}`));
  const requestJson = readText(`test-vectors/v3/openings/${entry.request_file}`);
  assert.equal(openRequestCommitment(payload, requestJson, Buffer.from(entry.salt_hex, "hex").subarray(0, 31)).code, "REQUEST_COMMITMENT_MISMATCH");
  // Unavailable means only that the opening material is missing; a signed commitment of the wrong form is malformed.
  assert.equal(openRequestCommitment(payload, requestJson, null).code, "REQUEST_COMMITMENT_UNAVAILABLE");
  assert.equal(openRequestCommitment(payload, undefined, Buffer.alloc(32)).code, "REQUEST_COMMITMENT_UNAVAILABLE");
  assert.equal(openRequestCommitment({ ...payload, requestCommitment: undefined }, requestJson, Buffer.alloc(32)).code, "REQUEST_COMMITMENT_MALFORMED");
  assert.equal(openRequestCommitment({ ...payload, requestCommitment: "sha256:XYZ" }, requestJson, Buffer.alloc(32)).code, "REQUEST_COMMITMENT_MALFORMED");
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

test("an unknown projection tag fails closed as unsupported, even with a valid signature; a projection that names no tag is malformed", () => {
  const payload = decode(read("test-vectors/v3/approve-human-execute-lane-refund.json"));
  for (const projection of ['{"projection":"execute/v2"}', '{"projection":"deploy_gate/v3"}', '{"projection":"deploy_gate/v9"}', '{"projection":""}']) {
    const result = verifyArtifact(signedEnvelope({ ...payload, publicProjectionJson: projection }), keys);
    assert.equal(result.code, "PROJECTION_UNSUPPORTED", projection);
    assert.equal(result.exitCode, 8);
  }
  // No build rule, under any tag, produces these: a malformed receipt, not a newer one.
  for (const projection of ['{"intent":{"name":"x"}}', '{"projection":7}', "not json", '["execute/v1"]', '"execute/v1"', "null", undefined]) {
    const signed = { ...payload, publicProjectionJson: projection };
    if (projection === undefined) delete signed.publicProjectionJson;
    const result = verifyArtifact(signedEnvelope(signed), keys);
    assert.equal(result.code, "MALFORMED", String(projection));
    assert.equal(result.exitCode, 3);
  }
  // A jcs_v3 payload is receipt version 3.
  for (const receiptVersion of [2, 4, "3", undefined]) {
    const signed = { ...payload, receiptVersion };
    if (receiptVersion === undefined) delete signed.receiptVersion;
    const result = verifyArtifact(signedEnvelope(signed), keys);
    assert.equal(result.code, "MALFORMED", String(receiptVersion));
    assert.equal(result.exitCode, 3);
  }
});

test("a signed requestCommitment that is missing or not sha256:<64 lowercase hex> is malformed (3), for every verifier", () => {
  const payload = decode(read("test-vectors/v3/approve-human-execute-lane-refund.json"));
  for (const requestCommitment of [undefined, "sha256:XYZ", `sha256:${"A".repeat(64)}`, "7cf143f6cad103ccdc2cf1d026420650de227501d16883f896eac5c23caec0c1", 7]) {
    const signed = { ...payload, requestCommitment };
    if (requestCommitment === undefined) delete signed.requestCommitment;
    const result = verifyArtifact(signedEnvelope(signed), keys);
    assert.equal(result.code, "REQUEST_COMMITMENT_MALFORMED", String(requestCommitment));
    assert.equal(result.exitCode, 3);
  }
  // Checked with the other well-formedness rules, before the projection and the decider proof (as the issuer's public check does).
  const both = verifyArtifact(signedEnvelope({ ...payload, requestCommitment: "sha256:XYZ", publicProjectionJson: '{"projection":"execute/v1","tenantId":"co_1"}' }), keys);
  assert.equal(both.code, "REQUEST_COMMITMENT_MALFORMED");
  // One meaning per code: unavailable (8) is missing opening material only; malformed (3) is the signed form.
  assert.equal(EXIT_CODES.REQUEST_COMMITMENT_MALFORMED, 3);
  assert.equal(EXIT_CODES.REQUEST_COMMITMENT_UNAVAILABLE, 8);
});

test("--summary reads the file less exactly one trailing line ending", () => {
  assert.equal(summaryFromFile("Approved"), "Approved");
  assert.equal(summaryFromFile("Approved\n"), "Approved");
  assert.equal(summaryFromFile("Approved\r\n"), "Approved");
  assert.equal(summaryFromFile("Approved\n\n"), "Approved\n");
  assert.equal(summaryFromFile("Approved\r"), "Approved\r");
  assert.equal(summaryFromFile(" Approved "), " Approved ");
  assert.equal(summaryFromFile("\n"), "");
  assert.equal(summaryFromFile(""), "");
});

test("the key and the signature are checked before the canonicalization: only a verified signature over an unknown one is unsupported", () => {
  const payload = decode(read("test-vectors/v3/approve-human-deploy-gate-private-repo.json"));
  const forged = (fields, keyId = payload.signatureKeyId) => {
    const envelope = signedEnvelope({ ...payload, ...fields, signatureKeyId: keyId });
    envelope.artifact.signature_b64 = Buffer.alloc(64, 1).toString("base64");
    return envelope;
  };
  // A rewritten payload with a recomputed hash and a garbage signature is a bad signature, not "unsupported".
  assert.equal(verifyArtifact(forged({ canonicalization: "jcs_v4" }), keys).code, "SIGNATURE_INVALID");
  assert.equal(verifyArtifact(forged({ canonicalization: "jcs_v4" }), keys).exitCode, 1);
  // Under a key nobody publishes, it is a missing key.
  assert.equal(verifyArtifact(forged({ canonicalization: "jcs_v4" }, "pp-nobody"), keys).code, "KEY_NOT_FOUND");
  // Signed for real: unsupported, unverifiable here, not tampered.
  const genuine = verifyArtifact(signedEnvelope({ ...payload, canonicalization: "jcs_v4" }), keys);
  assert.equal(genuine.code, "CANONICALIZATION_UNSUPPORTED");
  assert.equal(genuine.exitCode, 8);
});

test("a JSON key named __proto__ is an ordinary key: it stays in the canonical form, and a decider proof that carries one is invalid", () => {
  const payload = decode(read("test-vectors/v3/approve-human-deploy-gate-private-repo.json"));
  // Built from text so "__proto__" is an own key, as JSON.parse makes it.
  for (const inner of ['{"counter":17}', '"x"', "null"]) {
    const text = JSON.stringify(sortDeep(payload)).replace('"deciderProof":{', `"deciderProof":{"__proto__":${inner},`);
    const signed = JSON.parse(text);
    assert.ok(Object.prototype.hasOwnProperty.call(signed.deciderProof, "__proto__"));
    assert.equal(canonicalize(signed, "jcs_v3"), text, "the canonical form keeps the key");
    const bytes = Buffer.from(text, "utf8");
    const digest = signingDigest(bytes);
    const envelope = {
      artifact: {
        receipt_id: payload.id, key_id: payload.signatureKeyId, alg: "ed25519", signed_payload_hash: digest.toString("hex"),
        signature_b64: sign(null, digest, testKey).toString("base64"), payload_bytes_b64: bytes.toString("base64"),
      },
    };
    const result = verifyArtifact(envelope, keys);
    assert.equal(result.code, "DECIDER_PROOF_INVALID", inner);
    assert.equal(result.exitCode, 9);
    assert.equal(checkDeciderProof(signed.deciderAuthMethod, signed.deciderProof).code, "DECIDER_PROOF_INVALID");
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
  assert.throws(() => buildPublicProjection("deploy_gate/v3", "{}"), (error) => error.code === "PROJECTION_UNSUPPORTED");
  // The tag each lane signs today, as the issuer's map (app public-projection.ts, from the mint change that follows app #688).
  assert.deepEqual(PROJECTION_TAG_BY_LANE, { deploy_gate: "deploy_gate/v2", execute: "execute/v1", revocation: "revocation/v1" });
});

// ---------------------------------------------------------------------------
// deploy_gate/v2 (SPEC.md sections 3.4, 3.6, 3.7 and 6.7): deploy_gate/v1 with
// the matched policy rule's id and version (‡) projected only when the request
// records scope.visibility "public".
// ---------------------------------------------------------------------------

const POLICY_IDENTITY = ["policy.decision.ruleId", "policy.decision.ruleVersion", "metadata.denial.ruleId", "metadata.override.ruleId", "metadata.override.ruleVersion"];

/** A copy of `value` without the dotted paths, pruning containers left empty. */
function without(value, paths) {
  const copy = structuredClone(value);
  for (const path of paths) {
    const keys = path.split(".");
    const chain = [copy];
    for (const key of keys.slice(0, -1)) chain.push(chain[chain.length - 1]?.[key]);
    if (chain[chain.length - 1] && typeof chain[chain.length - 1] === "object") delete chain[chain.length - 1][keys[keys.length - 1]];
    for (let index = chain.length - 1; index > 0; index -= 1) {
      if (chain[index] && typeof chain[index] === "object" && Object.keys(chain[index]).length === 0) delete chain[index - 1][keys[index - 1]];
    }
  }
  return copy;
}

const ruleRequest = (visibility) => ({
  intent: { name: "deploy_gate_policy_override", category: "deployment" },
  scope: { commitSha: "3c9e1f0a7b2d4c6e8f0a1b3c5d7e9f1a2b4c6d8e", repo: "acme/app", ...(visibility === undefined ? {} : { visibility }) },
  policy: { decision: { outcome: "denied", ruleId: "deny.deterministic_dangerous_diff", ruleVersion: "outcome-router-v1", matchedInputs: { changeClass: "unclassified" } } },
  metadata: {
    denial: { category: "policy", decisionClass: "classifier", ruleId: "deny.deterministic_dangerous_diff", final: false },
    override: { overriddenDecisionClass: "classifier", ruleId: "deny.deterministic_dangerous_diff", ruleVersion: "outcome-router-v1", nextState: "approved" },
  },
});

test("deploy_gate/v2: the ‡ paths are exactly the matched rule's id and version, and only deploy_gate/v2 marks them", () => {
  assert.deepEqual(PROJECTION_ALLOWLISTS["deploy_gate/v2"].filter((field) => field.policyIdentity).map((field) => field.path), POLICY_IDENTITY);
  assert.deepEqual(
    Object.keys(PROJECTION_ALLOWLISTS).filter((tag) => tagWithholdsPolicyIdentity(tag)),
    ["deploy_gate/v2"]
  );
  assert.equal(tagWithholdsPolicyIdentity("deploy_gate/v3"), false);
  // Every ‡ path is a deploy_gate/v1 path, and is otherwise unchanged (a value slot, no † mark).
  for (const path of POLICY_IDENTITY) {
    const v1 = PROJECTION_ALLOWLISTS["deploy_gate/v1"].find((field) => field.path === path);
    const v2 = PROJECTION_ALLOWLISTS["deploy_gate/v2"].find((field) => field.path === path);
    assert.ok(v1 && !v1.policyIdentity && !v1.id && !v1.oneOf && !v1.repositoryIdentity, path);
    assert.deepEqual({ ...v2, policyIdentity: undefined }, { ...v1, policyIdentity: undefined }, path);
  }
});

test("deploy_gate/v2 build rule: ‡ paths follow scope.visibility exactly as † paths do; deploy_gate/v1 keeps publishing them", () => {
  for (const visibility of [undefined, "private", "internal", "PUBLIC", true, { public: true }]) {
    const requestJson = JSON.stringify(ruleRequest(visibility));
    const v1 = JSON.parse(buildPublicProjection("deploy_gate/v1", requestJson));
    const v2 = JSON.parse(buildPublicProjection("deploy_gate/v2", requestJson));
    const text = JSON.stringify(v2);
    assert.ok(!text.includes("deny.deterministic_dangerous_diff") && !text.includes("outcome-router-v1"), `${String(visibility)}: ${text}`);
    assert.equal(v1.policy.decision.ruleId, "deny.deterministic_dangerous_diff", String(visibility));
    // Everything else is deploy_gate/v1's: the outcome, the class, the finality, the override's next state.
    assert.deepEqual({ ...v2, projection: "deploy_gate/v1" }, without(v1, POLICY_IDENTITY), String(visibility));
    assert.equal(v2.policy.decision.outcome, "denied");
    assert.equal(v2.metadata.denial.decisionClass, "classifier");
    assert.equal(v2.metadata.override.nextState, "approved");
    assert.equal(v2.scope.repo, undefined, "† still applies");
  }
  // A public repository: deploy_gate/v1's projection, under the new tag.
  const publicJson = JSON.stringify(ruleRequest("public"));
  assert.deepEqual(
    JSON.parse(buildPublicProjection("deploy_gate/v2", publicJson)),
    { ...JSON.parse(buildPublicProjection("deploy_gate/v1", publicJson)), projection: "deploy_gate/v2" }
  );
  // A rule alone, without the rest of its decision, prunes to nothing.
  assert.equal(buildPublicProjection("deploy_gate/v2", '{"metadata":{"denial":{"ruleId":"r"}},"policy":{"decision":{"ruleId":"r","ruleVersion":"v"}}}'), '{"projection":"deploy_gate/v2"}');
});

test("deploy_gate/v2 projection check: a ‡ path without scope.visibility \"public\" is policy rule identity, a policy failure", () => {
  const check = (projection) => projectionProblem(JSON.stringify(sortDeep(projection)));
  for (const path of POLICY_IDENTITY) {
    const keys = path.split(".");
    const projection = { projection: "deploy_gate/v2" };
    let level = projection;
    for (const key of keys.slice(0, -1)) level = level[key] = {};
    level[keys[keys.length - 1]] = "hold.repo_protected_path";
    for (const scope of [undefined, { visibility: "private" }]) {
      const value = scope ? { ...projection, scope } : projection;
      assert.equal(check(value), `${path} is policy rule identity and scope.visibility is not "public"`, `${path} ${JSON.stringify(scope)}`);
      const result = checkPublicProjection(JSON.stringify(sortDeep(value)));
      assert.equal(result.code, "PROJECTION_NOT_ALLOWED");
      assert.equal(result.message, `deploy_gate/v2: ${path} is policy rule identity and scope.visibility is not "public"`);
      // deploy_gate/v1 is frozen: the same projection under it is allowed.
      assert.equal(check({ ...value, projection: "deploy_gate/v1" }), null, path);
    }
    assert.equal(check({ ...projection, scope: { visibility: "public" } }), null, path);
  }
  // A ‡ path keeps its slot: a value, so an object is still refused for what it is.
  assert.match(check({ projection: "deploy_gate/v2", scope: { visibility: "public" }, policy: { decision: { ruleId: { id: "x" } } } }), /scalar or an array of scalars/);
});

test("deploy_gate/v2 vectors: a private repository's rule is nowhere in the signed bytes, reasonCodes included; the committed request keeps it", () => {
  for (const name of ["approve-human-deploy-gate-v2-private-repo.json", "deny-policy-deploy-gate-v2-private-repo.json"]) {
    const vector = read(`test-vectors/v3/${name}`);
    const text = Buffer.from(vector.artifact.payload_bytes_b64, "base64").toString("utf8");
    assert.equal(vector.projection.projection, "deploy_gate/v2");
    assert.equal(vector.projection.scope.visibility, "private");
    const request = JSON.parse(readText(`test-vectors/v3/openings/${name.replace(/\.json$/, ".request.json")}`));
    const recorded = [request.policy?.decision?.ruleId, request.policy?.decision?.ruleVersion, request.metadata?.denial?.ruleId, request.metadata?.override?.ruleId, request.metadata?.override?.ruleVersion].filter(Boolean);
    assert.ok(recorded.length >= 2, `${name} commits its rule`);
    for (const value of recorded) assert.ok(!text.includes(value), `${name}: ${value} is in the signed bytes`);
    assert.ok(!text.includes('"ruleId"') && !text.includes('"ruleVersion"'), name);
    // The decision itself stays public.
    assert.equal(vector.projection.policy.decision.outcome, request.policy.decision.outcome);
    // A rule-carrying code names the rule only for a public repository (SPEC.md 3.4).
    for (const code of JSON.parse(vector.receipt.reasonCodes)) assert.ok(!recorded.includes(code), `${name}: reason code ${code}`);
  }
  const denial = read("test-vectors/v3/deny-policy-deploy-gate-v2-private-repo.json");
  assert.equal(denial.receipt.reasonCodes, '["DEPLOY_GATE_DENIED"]');
  assert.equal(denial.receipt.deciderId, "system/pp-engine");
  assert.deepEqual(denial.projection.metadata.denial, { category: "policy", decisionClass: "classifier", final: false, requireNewRequest: true });
  // The public repository's receipt publishes the rule, as deploy_gate/v1 does.
  const open = read("test-vectors/v3/approve-human-deploy-gate-v2-public-repo.json");
  assert.equal(open.projection.scope.visibility, "public");
  assert.equal(open.projection.scope.repo, "acme/docs-site");
  assert.equal(`${open.projection.policy.decision.ruleId}@${open.projection.policy.decision.ruleVersion}`, "hold.protected_path@outcome-router-v1");
});

test("deploy_gate/v1 vectors are frozen history: they name their tag, keep it, and verify as before", () => {
  for (const name of ["approve-human-deploy-gate-private-repo.json", "approve-human-deploy-gate-public-repo.json"]) {
    const vector = read(`test-vectors/v3/${name}`);
    const requestJson = readText(`test-vectors/v3/openings/${name.replace(/\.json$/, ".request.json")}`);
    assert.equal(vector.projection.projection, "deploy_gate/v1", name);
    assert.equal(buildPublicProjection("deploy_gate/v1", requestJson), vector.receipt.publicProjectionJson, name);
    const result = verifyArtifact(vector, keys);
    assert.equal(result.ok, true, result.message);
    assert.equal(result.ruleWithheld, false, name);
    assert.equal(result.rule, ruleOf(JSON.parse(requestJson)), name);
  }
  // The pin is load-bearing: under the lane's tag today, the private one would no longer publish its rule.
  const privateJson = readText("test-vectors/v3/openings/approve-human-deploy-gate-private-repo.request.json");
  assert.notEqual(buildPublicProjection(PROJECTION_TAG_BY_LANE.deploy_gate, privateJson), read("test-vectors/v3/approve-human-deploy-gate-private-repo.json").receipt.publicProjectionJson);
});

test("section 6.7: a withheld rule is reported as withheld, never as policyVersion, and named once the commitment is opened", () => {
  const cases = [
    ["approve-human-deploy-gate-v2-private-repo.json", true, null],
    ["deny-policy-deploy-gate-v2-private-repo.json", true, null],
    ["approve-human-deploy-gate-v2-public-repo.json", false, "hold.protected_path@outcome-router-v1"],
    ["approve-human-execute-lane-refund.json", false, null],
    ["revoke-human-deploy-gate.json", false, null],
  ];
  for (const [name, withheld, rule] of cases) {
    const vector = read(`test-vectors/v3/${name}`);
    const result = verifyArtifact(vector, keys);
    assert.equal(result.ok, true, result.message);
    assert.equal(result.ruleWithheld, withheld, name);
    assert.equal(result.rule, rule, name);
    assert.equal(ruleWithheldFrom(result.projectionTag, result.projection), withheld, name);
    const entry = openings.find((candidate) => candidate.receipt_vector === name && candidate.expected === "opened");
    const requestJson = readText(`test-vectors/v3/openings/${entry.request_file}`);
    const opened = verifyArtifact(vector, keys, { opening: { requestJson, salt: Buffer.from(entry.salt_hex, "hex") } });
    assert.equal(opened.ok, true, opened.message);
    assert.equal(opened.committedRule, withheld ? ruleOf(JSON.parse(requestJson)) : null, name);
  }
  // The policy engine's denial signs policyVersion deploy-gate-v1; it is never shown as the rule.
  const denial = read("test-vectors/v3/deny-policy-deploy-gate-v2-private-repo.json");
  assert.equal(denial.receipt.policyVersion, "deploy-gate-v1");
  const cli = (args) => spawnSync(process.execPath, [join(root, "tools/verify.mjs"), ...args], { encoding: "utf8" });
  const entry = openings.find((candidate) => candidate.receipt_vector === "deny-policy-deploy-gate-v2-private-repo.json");
  const plain = cli([join(root, "test-vectors/v3/deny-policy-deploy-gate-v2-private-repo.json"), join(root, "test-vectors/keys.json")]);
  assert.equal(plain.status, 0, plain.stderr);
  const ruleLines = (stdout) => stdout.split("\n").filter((line) => line.startsWith("rule: "));
  assert.deepEqual(ruleLines(plain.stdout), ["rule: withheld (private repository): the signed projection carries no policy rule id or version; opening the request commitment shows it"]);
  assert.ok(plain.stdout.includes("policy: deploy-gate-v1"), "the policy version is reported as the policy");
  const opened = cli([
    join(root, "test-vectors/v3/deny-policy-deploy-gate-v2-private-repo.json"), join(root, "test-vectors/keys.json"),
    "--request", join(root, "test-vectors/v3/openings", entry.request_file), "--salt", entry.salt_hex,
  ]);
  assert.equal(opened.status, 0, opened.stderr);
  assert.deepEqual(ruleLines(opened.stdout), ["rule: withheld (private repository): the signed projection carries no policy rule id or version; the opened request commitment records deny.deterministic_dangerous_diff@outcome-router-v1"]);
  const published = cli([join(root, "test-vectors/v3/approve-human-deploy-gate-v2-public-repo.json"), join(root, "test-vectors/keys.json")]);
  assert.deepEqual(ruleLines(published.stdout), ["rule: hold.protected_path@outcome-router-v1"]);

  // No visibility recorded: treated as private, and said so. Signed for real with the test key.
  const payload = decode(read("test-vectors/v3/approve-human-deploy-gate-v2-private-repo.json"));
  const projection = JSON.parse(payload.publicProjectionJson);
  delete projection.scope.visibility;
  const unrecorded = verifyArtifact(signedEnvelope({ ...payload, publicProjectionJson: JSON.stringify(sortDeep(projection)) }), keys);
  assert.equal(unrecorded.ok, true, unrecorded.message);
  assert.equal(describeWithheldRule(unrecorded), "withheld (visibility not recorded, so treated as private): the signed projection carries no policy rule id or version; opening the request commitment shows it");
  assert.equal(describeWithheldRule({ ...unrecorded, commitmentOpened: true, committedRule: null }), "withheld (visibility not recorded, so treated as private): the signed projection carries no policy rule id or version; the opened request commitment records no rule");
  // The rule a request records: the decision's, else the override's, else the denial's.
  assert.equal(ruleOf(ruleRequest("private")), "deny.deterministic_dangerous_diff@outcome-router-v1");
  assert.equal(ruleOf({ metadata: ruleRequest("private").metadata }), "deny.deterministic_dangerous_diff@outcome-router-v1");
  assert.equal(ruleOf({ metadata: { denial: { ruleId: "deny.x" } } }), "deny.x");
  assert.equal(ruleOf({ metadata: { override: { ruleId: "deny.x" } } }), "deny.x");
  assert.equal(ruleOf({ policy: { decision: { ruleId: "deny.x" } } }), null);
  assert.equal(ruleOf({ policy: { decision: { ruleId: "deny.x" } } }, { decisionOnly: true }), null);
  assert.equal(ruleOf({}), null);
});

test("SPEC.md section 3.7 tables state exactly the allowlists tools/public-projection.mjs builds with", () => {
  const spec = readText("SPEC.md");
  const slotOf = (field) => (field.id ? "identifier" : field.oneOf ? `one of ${field.oneOf.map((value) => `\`${value}\``).join(", ")}` : "value");
  const tableRows = (tag) => {
    const start = spec.indexOf(`#### \`${tag}\``);
    assert.notEqual(start, -1, `SPEC.md has no table for ${tag}`);
    const rows = [];
    for (const line of spec.slice(start).split("\n").slice(1)) {
      if (line.startsWith("#")) break;
      const match = line.match(/^\| `([^`]+)` \| ([^|]+?) \| ([†‡]?) *\|$/);
      if (match) rows.push(`${match[1]} ${match[2]}${match[3] ? ` ${match[3]}` : ""}`);
    }
    return rows;
  };
  for (const [tag, fields] of Object.entries(PROJECTION_ALLOWLISTS)) {
    if (tag === "deploy_gate/v2") {
      // Stated as its difference from deploy_gate/v1: the table lists the ‡ paths, and nothing else changes.
      assert.deepEqual(tableRows(tag), fields.filter((field) => field.policyIdentity).map((field) => `${field.path} ${slotOf(field)} ‡`), `SPEC.md table for ${tag}`);
      assert.deepEqual(
        fields.map(({ policyIdentity, ...field }) => field),
        PROJECTION_ALLOWLISTS["deploy_gate/v1"].map((field) => ({ ...field })),
        "deploy_gate/v2 is deploy_gate/v1 path for path, in the same order, with the same slots and † marks"
      );
      assert.ok(spec.includes("`deploy_gate/v2` is the `deploy_gate/v1` table, path for path, in the same order, with the same slots and † marks."));
      continue;
    }
    assert.ok(fields.every((field) => !field.policyIdentity), `${tag} marks no ‡ path`);
    assert.deepEqual(tableRows(tag), fields.map((field) => `${field.path} ${slotOf(field)}${field.repositoryIdentity ? " †" : ""}`), `SPEC.md table for ${tag}`);
  }
});

test("SPEC.md section 3.4 lists exactly the jcs_v3 signed fields, and section 3.8 exactly the keys of each decider proof shape", () => {
  const spec = readText("SPEC.md");
  const section = spec.slice(spec.indexOf("### 3.4 "), spec.indexOf("### 3.5 "));
  const listLine = section.split("\n").find((line) => line.startsWith("`agentId`"));
  assert.deepEqual(listLine.match(/`([A-Za-z]+)`/g).map((name) => name.slice(1, -1)), [...SIGNED_FIELDS_V3].sort());
  const proofSection = spec.slice(spec.indexOf("### 3.8 "), spec.indexOf("## 4. "));
  const tables = proofSection.split(/\*\*`(webauthn|reauth)`\*\*/).slice(1);
  const keysOf = (text) => text.split("\n").map((line) => line.match(/^\| `([A-Za-z]+)` \|/)?.[1]).filter(Boolean);
  const full = {
    webauthn: { method: "webauthn", credentialIdHash: "a".repeat(64), challengeHash: "b".repeat(64), authenticatorDataHash: "c".repeat(64), userVerified: true, rpId: "x", origin: "https://x", reviewGeneration: 1, verifiedAt: "2026-10-06T00:00:00.000Z" },
    reauth: { method: "reauth", authTime: "2026-10-06T00:00:00.000Z", maxAgeMs: 1, verifiedAt: "2026-10-06T00:00:00.000Z" },
  };
  for (let index = 0; index < tables.length; index += 2) {
    const method = tables[index];
    assert.deepEqual(keysOf(tables[index + 1]).sort(), Object.keys(deciderProofFromEvidence({ ...full[method], counter: 1, boundRequestId: "r", boundScopeHash: "s" })).sort(), method);
  }
  assert.equal(tables.length, 4);
});

test("the issuer's golden jcs_v3 inputs, with the committed binding: committed request, commitment, proofs, digests and signatures", () => {
  // The inputs of permission-protocol/app tests/signing/receipt-canonicalization-golden.test.ts
  // (fixed fields, the fixed salt 0..31, fixed step-up evidence and the golden
  // key, 32 bytes of 0x09), once per decider kind. Before receiptBinding, the
  // issuer's signer at 6e611d95 gave commitment
  // sha256:8177915c995f5702e172d3ae27510f128aaa6e1f79c4c39e6188ff8bfa69eb85 and
  // digests 28d71600…, 326c2927… and e6ad3101…, which this repository's tools
  // reproduced byte for byte. The literals below add the row's binding under
  // receiptBinding (SPEC.md section 3.5) and are computed by this repository's
  // tools. CROSS-CHECK PENDING: the issuer's golden test must give the same
  // committed request, commitment, digests and signatures once its mint
  // commits receiptBinding (SPEC.md section 12).
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
  const summary = 'Ship it: "quoted" ünïcode — done';
  const binding = { companyId: "co_golden", idemKey: "deploy-gate:dgr_golden:5d41402abc4b2a76b9719d911017c592", inputHash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" };
  const salt = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const committed = committedRequestJson(request, summary, binding);
  assert.deepEqual(JSON.parse(committed), { ...JSON.parse(request), receiptBinding: binding, receiptSummary: summary });
  assert.equal(
    committed,
    '{"action":{"operation":"deploy","tool":"github-actions"},"context":{"environment":"production","reversibility":"REVERSIBLE"},"enrichmentSnapshot":{"summary":"PRIVATE-ENRICHMENT"},"intent":{"category":"deployment","name":"deploy_gate_approval","summary":"Deploy gate authorization approved"},"metadata":{"deployGateRequestId":"dgr_golden"},"policy":{"decision":{"matchedInputs":{"analysisComplete":true,"changeClass":"protected","changedPaths":["src/private/path.ts"],"defaultBranch":"main","repoPolicy":{"rationale":"PRIVATE-RATIONALE"},"targetBranch":"main"},"outcome":"approval_required","ruleId":"hold.protected_path","ruleVersion":"outcome-router-v1"},"expiresAt":"2026-10-05T12:00:00.000Z"},"receiptBinding":{"companyId":"co_golden","idemKey":"deploy-gate:dgr_golden:5d41402abc4b2a76b9719d911017c592","inputHash":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"},"receiptSummary":"Ship it: \\"quoted\\" ünïcode — done","scope":{"artifact_digest":null,"capability":"deploy:production","commitSha":"9f2c000000000000000000000000000000000001","env":"production","ref":"refs/heads/main","repo":"acme/private-app","visibility":"private","workflow":null}}'
  );
  const projection = buildPublicProjection("deploy_gate/v1", committed);
  assert.equal(
    projection,
    '{"action":{"operation":"deploy","tool":"github-actions"},"context":{"environment":"production","reversibility":"REVERSIBLE"},"intent":{"category":"deployment","name":"deploy_gate_approval"},"metadata":{"deployGateRequestId":"dgr_golden"},"policy":{"decision":{"matchedInputs":{"analysisComplete":true,"changeClass":"protected"},"outcome":"approval_required","ruleId":"hold.protected_path","ruleVersion":"outcome-router-v1"},"expiresAt":"2026-10-05T12:00:00.000Z"},"projection":"deploy_gate/v1","scope":{"capability":"deploy:production","commitSha":"9f2c000000000000000000000000000000000001","env":"production","visibility":"private"}}'
  );
  const commitment = requestCommitment(salt, committed);
  assert.equal(commitment, "sha256:a57c62d3a69c2ea9142b14395ddb2d22750f1a349df738535bd434cb3b27ec11");

  const webauthnEvidence = {
    method: "webauthn", credentialIdHash: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", challengeHash: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
    authenticatorDataHash: "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2", userVerified: true, counter: 42, rpId: "app.permissionprotocol.com", origin: "https://app.permissionprotocol.com",
    boundRequestId: "dgr_golden", boundScopeHash: "5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592", reviewGeneration: 2, verifiedAt: "2026-10-05T10:59:30.000Z",
  };
  const reauthEvidence = { method: "reauth", authTime: "2026-10-05T10:57:00.000Z", maxAgeMs: 300000, verifiedAt: "2026-10-05T10:59:30.000Z" };
  const goldenKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 9)]), format: "der", type: "pkcs8" });
  const goldenKeys = { keys: [{ key_id: "pp_golden_k1", alg: "ed25519", public_key_b64: "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=", status: "active" }] };
  const cases = [
    { method: "session", evidence: null, proof: null, sha256: "40989bb09d8bbc94e8bba92bc89d8fedc2f98376ba293ab904bb7db4613b3c60", signature: "Y+kVWVXIAIHCQvRAKCXoz+LULqIGd9zFQ6blKQVzNt/czU4KWLDj9rW0Zpg3OjMiin04x6+J+s/VvGQPyXIAAw==" },
    {
      method: "session_stepup_webauthn", evidence: webauthnEvidence,
      proof: '{"authenticatorDataHash":"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2","challengeHash":"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e","credentialIdHash":"7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069","method":"webauthn","origin":"https://app.permissionprotocol.com","reviewGeneration":2,"rpId":"app.permissionprotocol.com","userVerified":true,"verifiedAt":"2026-10-05T10:59:30.000Z"}',
      sha256: "ff36bda276857ec8ad6612d03941336922eb4f3bdc764429c4f6948243f76574", signature: "ov9JG7flwhSWgQ8vhpvaybXoyO89gDu2msA2F3rW/sBZyExCSYec8r8NVEO0BMu6+9R2Cr5WiN11ZFalsbNnCQ==",
    },
    {
      method: "session_reauth", evidence: reauthEvidence, proof: '{"authTime":"2026-10-05T10:57:00.000Z","maxAgeMs":300000,"method":"reauth","verifiedAt":"2026-10-05T10:59:30.000Z"}',
      sha256: "c6c720462d58fd0e84d5c6ada77c56ba60aa9eaaa8bea73cff18398fe9ee0a61", signature: "/I+rRKYfowt4xDZwi2WZ7Y0p1VV6bv11xTdIbrEODGwOX7VbbNIbV3KpwnHLQcnbAGnS/ZFadODAZFZqhIqpBw==",
    },
  ];
  for (const golden of cases) {
    const proof = deciderProofForSigning(golden.method, golden.evidence);
    assert.equal(proof ? canonicalDeciderProofJson(proof) : null, golden.proof, golden.method);
    const row = {
      id: "rcpt_dg_golden_0001", companyId: "co_golden", idemKey: "deploy-gate:dgr_golden:5d41402abc4b2a76b9719d911017c592", agentId: "github-actions", runId: "run-4242",
      requestJson: committed, inputHash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", status: "APPROVED", riskTier: null, policyVersion: "deploy-gate-v1",
      reasonCodes: '["DEPLOY_GATE_APPROVED"]', summary, deciderId: "user:u_golden", deciderDisplay: "octo-signer", deciderAuthMethod: golden.method, deciderProof: proof,
      resolutionType: "allow_once", attributionConfidence: "credentialed", scope: "production", receiptVersion: 3, canonicalization: "jcs_v3", signatureAlg: "ed25519",
      signatureKeyId: "pp_golden_k1", expiresAt: new Date("2026-10-05T12:00:00.000Z"), createdAt: new Date("2026-10-05T11:00:00.000Z"),
      requestCommitment: commitment, publicProjectionJson: projection,
    };
    const text = canonicalize(row, "jcs_v3");
    assert.ok(!text.includes("quoted") && !text.includes("receiptSummary"), "the summary is not signed");
    assert.ok(!text.includes("receiptBinding") && !text.includes("co_golden") && !text.includes(binding.idemKey) && !text.includes(binding.inputHash), "the binding is not signed");
    const digest = createHash("sha256").update(text, "utf8").digest();
    assert.equal(digest.toString("hex"), golden.sha256, golden.method);
    assert.equal(sign(null, digest, goldenKey).toString("base64"), golden.signature, golden.method);
    // The reference verifier accepts it and opens it with the summary the issuer stored.
    const envelope = signedEnvelope(JSON.parse(text), goldenKey);
    assert.equal(envelope.artifact.signed_payload_hash, golden.sha256);
    const result = verifyArtifact(envelope, goldenKeys, { opening: { requestJson: committed, salt, summary, binding } });
    assert.equal(result.ok, true, result.message);
    assert.equal(result.committedSummary, summary);
    assert.deepEqual(result.committedBinding, binding);
  }
});
