# Versioning

How this format changes, what a change costs, and what a verifier must do about it.

## Two version axes, one rule

A receipt carries two version fields inside its signed bytes:

| Field | Values today | What it versions |
|---|---|---|
| `receiptVersion` | `1`, `2`; `3` specified, not yet issued (integer) | The data model: which fields exist and what they mean. |
| `canonicalization` | `jcs_v1`, `jcs_v2`; `jcs_v3` specified, not yet issued | The exact signed field set and the byte construction the signature covers. |

Execution attestations (SPEC.md section 9) are separate signed objects with their own pair: `attestationVersion` (`1`) and `canonicalization` (`attest_v1`). The same rules below apply to them; an attestation identifier is never a `jcs_v*` value and a receipt identifier is never an `attest_v*` value.

The rule that governs both: **a canonicalization version is frozen the moment a receipt is signed under it.** The bytes it produces are the signing truth for every receipt stamped with that value, forever. A new signed field set, a changed type for a signed field, or a changed serialization rule requires a new `canonicalization` string. An existing one is never edited.

A verifier dispatches on the receipt's own `canonicalization` value and rebuilds the bytes under the rules that value names. That is why a receipt signed in 2026 verifies in 2036 with or without Permission Protocol.

## New versions are additive; unknown ones fail closed

A new canonicalization version is added next to the old ones. It never changes how a receipt signed under an older value verifies, and no receipt is re-signed, rewritten or migrated to it. `jcs_v3` (`SPEC.md` sections 3.4 to 3.7) is the first version that removes signed fields. `jcs_v1` and `jcs_v2` receipts keep `companyId`, `idemKey`, `requestJson` and `inputHash` in their bytes and verify by their own rules forever.

A verifier that does not implement a receipt's `canonicalization` MUST report it as unsupported (`CANONICALIZATION_UNSUPPORTED` in `tools/verify.mjs`): unverifiable by that verifier, not tampered. It MUST NOT re-canonicalize the bytes under another version's list. A verifier written before `jcs_v3` therefore fails closed on a `jcs_v3` receipt rather than calling it valid or tampered.

## Adding a field

1. An **unsigned** field (metadata outside the signed set, such as `redeemedAt`) can be added at any time. It is not authenticated and verifiers MUST NOT trust it as such.
2. A **signed** field requires a new `canonicalization` value (`jcs_v4` next) and, if it changes what the receipt means, a new `receiptVersion`. The old value keeps verifying old receipts; new receipts carry the new value. All are documented side by side in `SPEC.md`, the way `jcs_v1`, `jcs_v2` and `jcs_v3` are.
3. The new field's absence on older receipts is not an error. A verifier reads the version and applies that version's required list.

## Deprecating a field

A signed field is never removed from a canonicalization version, because removing it changes the bytes of every receipt already signed under it. Deprecation means:

1. The next `canonicalization` version omits the field from its signed set.
2. `SPEC.md` marks the field as present in older versions only, with the date the last receipts carrying it were minted.
3. Verifiers keep the old field rules for the old version. Nothing is re-signed, backdated, or migrated.

`jcs_v3` is the first deprecation: it omits `companyId`, `idemKey`, `requestJson` and `inputHash` from its signed set, and binds the request through `requestCommitment` and `publicProjectionJson` instead. Because it removes signed fields, it also moves `receiptVersion` to `3`. Receipts carrying the old fields stay valid.

## Projection tags

A `jcs_v3` receipt's `publicProjectionJson` names the allowlist it was built under: `deploy_gate/v1`, `execute/v1` or `revocation/v1` (`SPEC.md` section 3.7). A tag is frozen the moment a receipt is signed with it, under the same rule as a canonicalization version.

- A new lane, or any change to an allowlist (a path added, removed, or given a different slot or visibility rule), gets a new tag such as `deploy_gate/v2`. A shipped tag is never edited.
- A new tag does not need a new canonicalization version, because the signed field set and the byte rules stay the same. It does need a `SPEC.md` table and a version-history entry here before any receipt carries it.
- A verifier that does not know a tag fails closed (`PROJECTION_UNSUPPORTED`): it cannot check the projection against an allowlist it lacks.

## Widening a value set

Adding an allowed value to an existing signed string field (for example a new `deciderAuthMethod` such as a step-up authentication method) does **not** change the bytes of any existing receipt, so it does not require a new canonicalization version. It does require:

1. A `SPEC.md` update naming the new value and the date it first appears.
2. A schema update that accepts the new value.
3. Verifiers that reject unknown values MUST treat that rejection as a policy failure, not a signature failure. The signature is still valid.

## What breaks a major version

Any of the following is a breaking change and gets a new `receiptVersion` and a new `canonicalization`:

- Changing the signature input (today: the SHA-256 digest of the canonical UTF-8 bytes).
- Changing the algorithm or the key identification scheme.
- Changing the type or serialization of an existing signed field.
- Removing a signed field or making a required one optional.
- Changing the meaning of `status`, `deciderId` prefixes, or `scope`.

## What never changes

- `signatureAlg` is `ed25519` in every version published so far. Algorithm agility is a new major version, never a silent swap, and downgrades are never accepted.
- Old receipts are never re-signed, mutated, or backdated. If a defect is found in how a field was populated, the fix is forward-only and the affected window is documented (see `SPEC.md`, "Known windows").

## Version history

| Date | Change | Version markers |
|---|---|---|
| 2026-04 | First published format (`RECEIPT-FORMAT-V1.md`) | `receiptVersion` `v1` (string, in the fixtures), `jcs_v1` |
| 2026-07-09 | Decider bound inside the signature: six attribution fields added | `receiptVersion` `2`, `jcs_v2` |
| 2026-08-11 | Execute-lane decisions signed at decision time with a role-class decider | no version change (values only) |
| 2026-09-08 | `SPEC.md` documents the format as emitted, including the digest signature input and the string types the hosted service uses; `prev` reserved for `jcs_v3` | no version change (documentation) |
| 2026-10-03 | Step-up signing values `session_stepup_webauthn` and `session_reauth` for `deciderAuthMethod`, observed on production receipts by this date; documented here | no version change (values only) |
| 2026-10 | Execution attestations: the execute lane signs the authorization before the action and records the outcome as a separate signed attestation (ADR 0003); execute-lane human approvals signed at the decision are `credentialed` | `attestationVersion` `1`, `attest_v1` (attestations); receipts unchanged |
| 2026-10-06 | Receipt format v3 specified: the signed bytes carry a salted `requestCommitment` and an allowlisted `publicProjectionJson` instead of `companyId`, `idemKey`, `requestJson` and `inputHash`. Specified before issuance; the hosted service has not issued one yet, and the date it first does will be added here. `prev` moves to `jcs_v4` | `receiptVersion` `3`, `jcs_v3`; projection tags `deploy_gate/v1`, `execute/v1`, `revocation/v1` |

## Reserved names

`prev` is reserved for `jcs_v4`. `jcs_v3` is the receipt-privacy change alone and does not carry it. See `SPEC.md`, "Chaining".
