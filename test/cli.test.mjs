// The reference verifier as a command (VERIFY.md), on every platform.
//
//   node --test "test/*.test.mjs"
//
// tools/verify.mjs runs as a command only when it is the entry point. Until
// that check used pathToFileURL, it never matched on Windows: the command ran
// nothing and exited 0, the code for "verified", for any input, tampered
// receipts included. So every case here asserts what the command printed as
// well as its exit code, and CI runs this file on Linux and Windows.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { EXIT_CODES } from "../tools/verify.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const keys = join(root, "test-vectors/keys.json");

function run(args, options = {}) {
  return spawnSync(process.execPath, args, { encoding: "utf8", cwd: root, ...options });
}

test("a genuine receipt verifies: exit 0 and a VERIFIED line", () => {
  const result = run([join(root, "tools/verify.mjs"), join(root, "test-vectors/approve-human-deploy-gate.json"), keys]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^VERIFIED rcpt_/);
});

test("the tampered jcs_v2 vector is rejected: exit 1, SIGNATURE_INVALID", () => {
  const result = run([join(root, "tools/verify.mjs"), join(root, "test-vectors/tampered-approve-human-deploy-gate.json"), keys]);
  assert.equal(result.status, EXIT_CODES.SIGNATURE_INVALID);
  assert.match(result.stderr, /^FAILED SIGNATURE_INVALID/);
  assert.doesNotMatch(result.stdout, /VERIFIED/);
});

test("the tampered jcs_v3 vector is rejected: exit 1, SIGNATURE_INVALID", () => {
  const result = run([join(root, "tools/verify.mjs"), join(root, "test-vectors/v3/tampered-approve-human-deploy-gate-private-repo.json"), keys]);
  assert.equal(result.status, EXIT_CODES.SIGNATURE_INVALID);
  assert.match(result.stderr, /^FAILED SIGNATURE_INVALID/);
});

test("invoked as VERIFY.md shows, by a path relative to the repository, the tampered vector is still rejected", () => {
  const result = run(["tools/verify.mjs", "test-vectors/tampered-approve-human-deploy-gate.json", "test-vectors/keys.json"]);
  assert.equal(result.status, EXIT_CODES.SIGNATURE_INVALID);
  assert.match(result.stderr, /^FAILED SIGNATURE_INVALID/);
});

test("with no arguments the command prints its usage and exits 64", () => {
  const result = run([join(root, "tools/verify.mjs")]);
  assert.equal(result.status, 64);
  assert.match(result.stderr, /^usage: node tools\/verify\.mjs/);
});
