# Permission Protocol Receipt Format

The open specification for the signed authority receipt that [Permission Protocol](https://permissionprotocol.com) issues for each gated action, written from the code that emits it, with signed test vectors and a dependency-free reference verifier.

A receipt is a signed statement that a specific decision (approve or deny) was made about a specific action, by a specific decider, under a specific policy version, at a specific time. It verifies with the issuer's published public key and nothing else, so it stays evidence after the vendor is gone.

## Read

| Document | What it covers |
|---|---|
| [`SPEC.md`](./SPEC.md) | **Current.** Field-by-field semantics of the format as emitted today (`receiptVersion` 2, `jcs_v2`), canonicalization, the Ed25519-over-SHA-256 signature, key distribution, the verify procedure, decision and decider semantics, chaining. |
| [`VERIFY.md`](./VERIFY.md) | Verify a receipt offline in nine lines, plus the online paths. |
| [`MAPPINGS.md`](./MAPPINGS.md) | Which receipt fields back which controls in AIUC-1, the CSA Agentic Trust Framework, and NIST AI RMF. Three statuses: implements, provides evidence for, not addressed. |
| [`VERSIONING.md`](./VERSIONING.md) | How fields are added and deprecated, what breaks a major version, what never changes. |
| [`RECEIPT-FORMAT-V1.md`](./RECEIPT-FORMAT-V1.md) | Frozen. The first published document (`jcs_v1`). Kept as published, with errata recorded in `SPEC.md` section 5. |

## Use

| Path | What it is |
|---|---|
| [`schema/receipt-v2.json`](./schema/receipt-v2.json) | JSON Schema (draft 2020-12) for the decoded signed payload. |
| [`schema/artifact.json`](./schema/artifact.json) | JSON Schema for the portable envelope (`payload_bytes_b64`, `signature_b64`, `key_id`). |
| [`test-vectors/`](./test-vectors/) | Signed receipts: approve by a human, approve by the policy engine, deny by the kill switch, execute-lane human approvals signed before the action, one deliberately tampered, and one real production receipt captured from the live service; under `attestations/`, one signed execution attestation per outcome plus a tampered one. With the key sets that verify them. |
| [`tools/verify.mjs`](./tools/verify.mjs) | Reference verifier, no dependencies: `node tools/verify.mjs artifact.json keys.json`. |
| [`tools/canonicalize.mjs`](./tools/canonicalize.mjs) | Reference canonicalization for `jcs_v1` and `jcs_v2`. |
| [`tools/generate-vectors.mjs`](./tools/generate-vectors.mjs) | Regenerates the vectors deterministically; CI fails on drift. |
| [`test/`](./test/) | Conformance tests: `node --test "test/*.test.mjs"`. |
| [`fixtures/`](./fixtures/), [`conformance/`](./conformance/) | The v1 fixture suite and its script, unchanged. They exercise `RECEIPT-FORMAT-V1.md` and the `pp-cli` reference verifier for that document only. |

## Status

- `SPEC.md` describes what the hosted service at `app.permissionprotocol.com` has emitted since 2026-07-09. Every field is traced to the code path that writes it.
- Verified against a live production receipt on 2026-09-08 (`test-vectors/live-deploy-gate-approve.json`).
- Independent implementations are welcome. Open an issue for anything the document leaves ambiguous.

## License

The specification text (`*.md`) is licensed under [CC BY 4.0](./LICENSE-CC-BY-4.0). The schemas, test vectors, tools, and tests are licensed under [Apache License 2.0](./LICENSE).
