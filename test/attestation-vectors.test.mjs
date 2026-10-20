// Conformance tests for the execution attestation vectors (SPEC.md section 9).
//
//   node --test "test/*.test.mjs"
//
// Every vector under test-vectors/attestations/ names the receipt vector it
// attests. Each valid one must: verify its receipt first, re-canonicalize to
// its exact signed bytes under attest_v1, match its digest, verify its Ed25519
// signature against the key set, validate against schema/attestation-v1.json,
// and satisfy the section 9.2 consistency rules. The tampered one must fail at
// the signature.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { attestationBytes, outputHash } from "../tools/canonicalize.mjs";
import { attestationClaimProblem, verifyAttestationArtifact } from "../tools/verify.mjs";
import { validate } from "./mini-schema.mjs";

const root = new URL("..", import.meta.url).pathname;
const read = (relative) => JSON.parse(readFileSync(join(root, relative), "utf8"));
const schema = read("schema/attestation-v1.json");
const keys = read("test-vectors/keys.json");

const files = readdirSync(join(root, "test-vectors", "attestations")).filter((name) => name.endsWith(".json")).sort();

test("one signed vector per outcome, plus a tampered one", () => {
  const outcomes = files
    .filter((name) => !name.startsWith("tampered-"))
    .map((name) => read(`test-vectors/attestations/${name}`).attestation.outcome)
    .sort();
  assert.deepEqual(outcomes, ["failed", "succeeded", "unknown"]);
  assert.ok(files.some((name) => name.startsWith("tampered-")));
});

test("no two attestations attest the same receipt", () => {
  const ids = files
    .filter((name) => !name.startsWith("tampered-"))
    .map((name) => read(`test-vectors/attestations/${name}`).attestation_artifact.approval_receipt_id);
  assert.equal(new Set(ids).size, ids.length);
});

for (const name of files) {
  const vector = read(`test-vectors/attestations/${name}`);
  const receipt = read(`test-vectors/${vector.receipt_vector}`);
  const tampered = name.startsWith("tampered-");

  test(`${name}: payload bytes are the attest_v1 encoding of the payload`, () => {
    const bytes = Buffer.from(vector.attestation_artifact.payload_bytes_b64, "base64");
    const payload = JSON.parse(bytes.toString("utf8"));
    assert.ok(attestationBytes(payload).equals(bytes));
    assert.deepEqual(vector.attestation, payload, "attestation copy drifted from the signed bytes");
  });

  if (tampered) {
    test(`${name}: verification fails at the signature`, () => {
      const result = verifyAttestationArtifact(vector, keys, receipt);
      assert.equal(result.ok, false);
      assert.equal(result.code, "SIGNATURE_INVALID");
    });
    continue;
  }

  test(`${name}: verifies with its receipt and matches schema/attestation-v1.json`, () => {
    const result = verifyAttestationArtifact(vector, keys, receipt);
    assert.equal(result.ok, true, result.message);
    assert.deepEqual(validate(schema, result.attestation), []);
    assert.equal(attestationClaimProblem(result.attestation), null);
    assert.equal(result.receipt.status, "APPROVED");
    assert.equal(result.attestation.signatureKeyId, result.receipt.signatureKeyId, "same issuer key as the receipt");
  });
}

test("an attestation never verifies against a different receipt", () => {
  const vector = read("test-vectors/attestations/attest-succeeded-policy-execute-lane.json");
  const other = read("test-vectors/approve-human-execute-lane-refund.json");
  assert.equal(verifyAttestationArtifact(vector, keys, other).code, "RECEIPT_MISMATCH");
});

test("an attestation cannot attest a DENIED receipt", () => {
  const vector = structuredClone(read("test-vectors/attestations/attest-succeeded-policy-execute-lane.json"));
  const denied = read("test-vectors/deny-kill-switch-execute-lane.json");
  vector.attestation_artifact.approval_receipt_id = denied.artifact.receipt_id;
  assert.equal(verifyAttestationArtifact(vector, keys, denied).code, "RECEIPT_NOT_APPROVED");
});

test("a withheld payload and an unsigned outcome are reported, never as tampering or as verified", () => {
  const vector = read("test-vectors/attestations/attest-succeeded-policy-execute-lane.json");
  const receipt = read("test-vectors/approve-policy-execute-lane.json");
  const withheld = structuredClone(vector);
  delete withheld.attestation_artifact.payload_bytes_b64;
  withheld.attestation_artifact.payload_withheld = true;
  assert.equal(verifyAttestationArtifact(withheld, keys, receipt).code, "PAYLOAD_WITHHELD");
  const unsigned = {
    attestation_artifact: { approval_receipt_id: receipt.artifact.receipt_id, outcome: "succeeded", attestation_version: 1, signed: false, signing_failed: true, issued_at: "2026-09-01T14:05:00.512Z" },
  };
  assert.equal(verifyAttestationArtifact(unsigned, keys, receipt).code, "ATTESTATION_UNSIGNED");
});

test("section 9.2 consistency rules", () => {
  const base = { approvalReceiptId: "r", attestationVersion: 1, canonicalization: "attest_v1", signatureAlg: "ed25519", signatureKeyId: "k", createdAt: "2026-09-01T00:00:00.000Z" };
  assert.match(attestationClaimProblem({ ...base, outcome: "unknown", finishedAt: "2026-09-01T00:00:00.000Z" }), /no finish/);
  assert.match(attestationClaimProblem({ ...base, outcome: "unknown", outputHash: outputHash({}) }), /no output/);
  assert.match(attestationClaimProblem({ ...base, outcome: "succeeded", startedAt: "2026-09-01T00:00:00.000Z" }), /start and a finish/);
  assert.match(attestationClaimProblem({ ...base, outcome: "failed", startedAt: "2026-09-01T00:00:01.000Z", finishedAt: "2026-09-01T00:00:00.000Z" }), /before/);
  assert.equal(attestationClaimProblem({ ...base, outcome: "unknown" }), null);
});

test("outputHash is sha256 over the canonical (sorted-key) JSON of the output", () => {
  assert.equal(outputHash({ b: 1, a: { d: 2, c: 3 } }), outputHash({ a: { c: 3, d: 2 }, b: 1 }));
  // Cross-checked against the hosted service's hashExecutionOutput on 2026-10-05.
  assert.equal(outputHash({ b: 1, a: { d: 2, c: 3 } }), "sha256:78d48859c3252943aab7306f76c80f3f07783582e05ab8f944ce0696f2dbfc67");
});
