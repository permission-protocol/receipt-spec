# Permission Protocol Receipt Format

The open specification for the signed authority receipt that [Permission Protocol](https://permissionprotocol.com) issues for each gated action, written from the code that emits it, with signed test vectors and a dependency-free reference verifier.

A receipt is a signed statement that a specific decision (approve or deny) was made about a specific action, by a specific decider, under a specific policy version, at a specific time. It verifies with the issuer's published public key and nothing else, so it stays evidence after the vendor is gone.

## Read

| Document | What it covers |
|---|---|
| [`SPEC.md`](./SPEC.md) | **Current.** Field-by-field semantics of the format as emitted today (`receiptVersion` 2, `jcs_v2`), canonicalization, the Ed25519-over-SHA-256 signature, key distribution, the verify procedure, decision and decider semantics, chaining. Also receipt format v3 (`receiptVersion` 3, `jcs_v3`, specified before issuance): a salted request commitment, with the summary committed inside it, and an allowlisted public projection replace the request and the summary in the signed bytes, and a decider who stepped up signs the evidence (sections 3.4 to 3.8, 6.7). |
| [`VERIFY.md`](./VERIFY.md) | Verify a receipt offline in nine lines, plus the online paths. |
| [`MAPPINGS.md`](./MAPPINGS.md) | Which receipt fields back which controls in AIUC-1, the CSA Agentic Trust Framework, and NIST AI RMF. Three statuses: implements, provides evidence for, not addressed. |
| [`VERSIONING.md`](./VERSIONING.md) | How fields are added and deprecated, what breaks a major version, what never changes. |
| [`RECEIPT-FORMAT-V1.md`](./RECEIPT-FORMAT-V1.md) | Frozen. The first published document (`jcs_v1`). Kept as published, with errata recorded in `SPEC.md` section 5. |

## Use

| Path | What it is |
|---|---|
| [`schema/receipt-v2.json`](./schema/receipt-v2.json) | JSON Schema (draft 2020-12) for the decoded signed payload. |
| [`schema/receipt-v3.json`](./schema/receipt-v3.json) | The same for a `jcs_v3` payload. |
| [`schema/artifact.json`](./schema/artifact.json) | JSON Schema for the portable envelope (`payload_bytes_b64`, `signature_b64`, `key_id`). |
| [`test-vectors/`](./test-vectors/) | Signed receipts: approve by a human, approve by the policy engine, deny by the kill switch, execute-lane human approvals signed before the action, one deliberately tampered, and one real production receipt captured from the live service; under `attestations/`, one signed execution attestation per outcome plus a tampered one; under `v3/`, `jcs_v3` receipts for the deploy gate (private and public repository, with a passkey and a re-authentication decider proof), the execute lane and a revocation, a tampered one, one whose signed projection breaks its allowlist, two whose signed decider proof is defective, and under `v3/openings/` the committed requests with their salts and summaries. With the key sets that verify them. |
| [`tools/verify.mjs`](./tools/verify.mjs) | Reference verifier, no dependencies: `node tools/verify.mjs artifact.json keys.json`. For `jcs_v3`, add `--request <file> --salt <hex>` to open the request commitment, and `--summary <file>` to check a stated summary against the committed one. |
| [`tools/canonicalize.mjs`](./tools/canonicalize.mjs) | Reference canonicalization for `jcs_v1`, `jcs_v2` and `jcs_v3`, the `jcs_v3` request commitment, and the committed summary (`receiptSummary`). |
| [`tools/public-projection.mjs`](./tools/public-projection.mjs) | The `jcs_v3` projection allowlists, the build rule, and the projection check every verifier runs. |
| [`tools/decider-proof.mjs`](./tools/decider-proof.mjs) | The `jcs_v3` decider proof shapes, the issuer's builder, and the decider proof check every verifier runs. |
| [`tools/generate-vectors.mjs`](./tools/generate-vectors.mjs) | Regenerates the vectors deterministically; CI fails on drift. |
| [`test/`](./test/) | Conformance tests: `node --test "test/*.test.mjs"`. |
| [`fixtures/`](./fixtures/), [`conformance/`](./conformance/) | The v1 fixture suite and its script, unchanged. They exercise `RECEIPT-FORMAT-V1.md` and the `pp-cli` reference verifier for that document only. |

## Status

- `SPEC.md` describes what the hosted service at `app.permissionprotocol.com` has emitted since 2026-07-09. Every field is traced to the code path that writes it.
- Verified against a live production receipt on 2026-09-08 (`test-vectors/live-deploy-gate-approve.json`).
- `jcs_v3` is specified before the hosted service issues it (2026-10-06). Its vectors were checked byte for byte against the issuer's final `jcs_v3` signing code (`SPEC.md` section 12).
- Independent implementations are welcome. Open an issue for anything the document leaves ambiguous.

## License

The specification text (`*.md`) is licensed under [CC BY 4.0](./LICENSE-CC-BY-4.0). The schemas, test vectors, tools, and tests are licensed under [Apache License 2.0](./LICENSE).
