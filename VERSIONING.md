# Versioning

How this format changes, what a change costs, and what a verifier must do about it.

## Two version axes, one rule

A receipt carries two version fields inside its signed bytes:

| Field | Values today | What it versions |
|---|---|---|
| `receiptVersion` | `1`, `2` (integer) | The data model: which fields exist and what they mean. |
| `canonicalization` | `jcs_v1`, `jcs_v2` | The exact signed field set and the byte construction the signature covers. |

The rule that governs both: **a canonicalization version is frozen the moment a receipt is signed under it.** The bytes it produces are the signing truth for every receipt stamped with that value, forever. A new signed field set, a changed type for a signed field, or a changed serialization rule requires a new `canonicalization` string. An existing one is never edited.

A verifier dispatches on the receipt's own `canonicalization` value and rebuilds the bytes under the rules that value names. That is why a receipt signed in 2026 verifies in 2036 with or without Permission Protocol.

## Adding a field

1. An **unsigned** field (metadata outside the signed set, such as `redeemedAt`) can be added at any time. It is not authenticated and verifiers MUST NOT trust it as such.
2. A **signed** field requires a new `canonicalization` value (`jcs_v3` next) and, if it changes what the receipt means, a new `receiptVersion`. The old value keeps verifying old receipts; new receipts carry the new value. Both are documented side by side in `SPEC.md`, the way `jcs_v1` and `jcs_v2` are today.
3. The new field's absence on older receipts is not an error. A verifier reads the version and applies that version's required list.

## Deprecating a field

A signed field is never removed from a canonicalization version, because removing it changes the bytes of every receipt already signed under it. Deprecation means:

1. The next `canonicalization` version omits the field from its signed set.
2. `SPEC.md` marks the field as present in older versions only, with the date the last receipts carrying it were minted.
3. Verifiers keep the old field rules for the old version. Nothing is re-signed, backdated, or migrated.

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

## Reserved names

`prev` is reserved for the next canonicalization version. See `SPEC.md`, "Chaining".
