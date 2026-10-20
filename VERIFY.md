# Verify a receipt

Two inputs, both public: the receipt's **artifact** (the exact signed bytes plus the signature) and the issuer's **key set**. Nothing else. No account, no API key, no Permission Protocol software.

## Offline, in nine lines

Save the artifact and the key set once, then verify with Node's built-in crypto whenever you like, with no network:

```bash
curl -sS https://app.permissionprotocol.com/r/RECEIPT_ID.json > artifact.json
curl -sS https://app.permissionprotocol.com/.well-known/permission-protocol/keys.json > keys.json
node -e '
const {createHash,createPublicKey,verify}=require("node:crypto"),fs=require("fs");
const a=JSON.parse(fs.readFileSync("artifact.json")).artifact, keys=JSON.parse(fs.readFileSync("keys.json")).keys;
const key=keys.find(k=>k.key_id===a.key_id); if(!key||key.status==="revoked") throw new Error("key unavailable");
const bytes=Buffer.from(a.payload_bytes_b64,"base64"), digest=createHash("sha256").update(bytes).digest();
if(digest.toString("hex")!==a.signed_payload_hash) throw new Error("hash mismatch");
const pk=createPublicKey({key:Buffer.concat([Buffer.from("302a300506032b6570032100","hex"),Buffer.from(key.public_key_b64,"base64")]),format:"der",type:"spki"});
console.log(verify(null,digest,pk,Buffer.from(a.signature_b64,"base64"))?"VERIFIED":"FAILED", JSON.parse(bytes).deciderDisplay);'
```

Or use the reference verifier in this repository, which also re-canonicalizes the payload and reports the decision and decider:

```bash
node tools/verify.mjs artifact.json keys.json
```

Exit codes: `0` verified, `1` signature invalid, `2` key not found or revoked, `3` malformed (including a `jcs_v3` payload that is not receipt version 3, whose signed `requestCommitment` is missing or not `sha256:<64 lowercase hex>` (`REQUEST_COMMITMENT_MALFORMED`), or whose projection is not JSON text of an object naming a tag), `4` payload bytes disagree with their hash or their own canonical form, `8` unverifiable here, not tampered: a canonicalization or projection tag this verifier does not support, `9` a `jcs_v3` policy failure: a projection outside its allowlist (`PROJECTION_NOT_ALLOWED`), or a decider proof that disagrees with `deciderAuthMethod` (`DECIDER_PROOF_MISMATCH`) or breaks its shape (`DECIDER_PROOF_INVALID`), `10` the private record supplied with a `jcs_v3` receipt does not match what was signed: the request, salt, summary and binding values do not open its commitment (`REQUEST_COMMITMENT_MISMATCH`, `COMMITTED_SUMMARY_MISMATCH`, `RECEIPT_BINDING_MISMATCH`, `PUBLIC_PROJECTION_MISMATCH`). The key and the signature are checked before the canonicalization, so only a genuine signature over an unknown canonicalization exits `8`.

## Receipt format v3 (`jcs_v3`)

A `jcs_v3` receipt (`SPEC.md` sections 3.4 to 3.8) signs a salted commitment to its request and a public projection of it, instead of the request. Its summary is not signed: it is committed inside the request, and so are the receipt's workspace (`companyId`), idempotency key (`idemKey`) and input hash (`inputHash`), under `receiptBinding`. A decider who stepped up at signing also signs the evidence, `deciderProof`. The nine lines above verify its signature unchanged. The reference verifier also checks that the projection stays within its tag's allowlist and that the decider proof agrees with `deciderAuthMethod`, which every verifier must do (`SPEC.md` section 6.7).

The workspace that owns the receipt holds the request text, its 32-byte salt, the stored summary and the stored binding values, and can open the commitment:

```bash
node tools/verify.mjs artifact.json keys.json --request request.json --salt SALT_HEX --summary summary.txt --binding binding.json
```

`SALT_HEX` is the salt as 64 hex characters. The owner artifact and evidence package carry all three as `request_json`, `request_commitment_salt_b64` and `summary` (`SPEC.md` 3.5): write `request_json`'s string value to `request.json` unchanged, write `summary`'s string value to `summary.txt` (the verifier drops exactly one trailing `\n` or `\r\n`, so `echo "$SUMMARY" > summary.txt` works; nothing else is trimmed), and convert the salt with `node -e "console.log(Buffer.from(process.argv[1], 'base64').toString('hex'))" "$SALT_B64"`. `request.json` must be the exact text the issuer committed to. The commitment covers it byte for byte, so a reformatted copy does not open it. `--summary` is optional; without it the verifier prints the committed summary without comparing it. `--binding` is optional too: `binding.json` is a JSON object holding any of `companyId`, `idemKey` and `inputHash`, taken from the owner fields `company_id`, `idem_key` and `input_hash`, and each one given must equal the committed `receiptBinding` value. Without it the verifier prints the committed binding without comparing it; a committed request without a well-formed `receiptBinding` fails either way (`RECEIPT_BINDING_MISMATCH`). An opening proves that the receipt was signed over exactly that request, summary and binding, and that its public projection was built from the request.

A `deploy_gate/v2` receipt on a private repository does not publish the policy rule that matched (`SPEC.md` section 3.7). The verifier's `rule:` line says the rule is withheld and never shows the policy version in its place. After an opening, the same line names the rule the committed request records.

## What the check proves

- The bytes in `payload_bytes_b64` were signed by the holder of the private key for `key_id`, and have not changed since.
- The decision (`status`), the decider (`deciderId`, `deciderDisplay`, `deciderAuthMethod`, `attributionConfidence`), the policy version, the action snapshot, and the timestamps inside those bytes are what the issuer committed to.

For a `jcs_v3` receipt, the action snapshot in the bytes is the public projection plus the commitment. The rest of the request, and the summary, are proved only to whoever opens the commitment.

It does not prove the action succeeded, that the decision was wise, or that the receipt is still valid for one-time redemption (`expiresAt` and redemption state are the issuer's concern, and the signature remains valid evidence after both).

## Online

- `https://app.permissionprotocol.com/r/RECEIPT_ID` renders the receipt and runs the issuer's full verification on every view; a receipt whose bytes do not match its signature is withheld and shown as unverified.
- `GET https://app.permissionprotocol.com/api/v1/public/receipts/RECEIPT_ID` returns the public fields with a `verification` block (`verified`, `signature_intact`, `signature_status`, `state`).
- `npx @permission-protocol/verify https://app.permissionprotocol.com/r/RECEIPT_ID` (from the `permission-protocol/app` monorepo, `permission-protocol-sdk/packages/verify`) downloads the artifact and key set and runs the same digest-and-signature check locally. It has no offline mode today; an issue is open to accept saved files.

## Tenant-authenticated artifact

Receipts whose public page is withheld, or that a tenant prefers not to expose publicly, are exported with an API key holding the `receipts.verify` scope from `GET /api/v1/receipts/RECEIPT_ID/artifact`. The envelope is the same shape and verifies the same way.

## A note on pp-cli

`permission-protocol/pp-cli` is the reference verifier for the **v1 fixture suite** in this repository (`fixtures/`). Those fixtures were signed over the raw canonical bytes and carry `canonicalization: jcs_v1`. The hosted service signs the SHA-256 digest of the canonical bytes and has emitted `jcs_v2` since 2026-07-09, so pp-cli does not verify receipts the product issues today. `SPEC.md` section 5 records this as an erratum to the v1 document; `tools/verify.mjs` is the current reference verifier.
