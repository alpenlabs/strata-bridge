# admin-tool

Inspect and sign an authorization to spend a specific claim's payout connector (`claim_txid:1`). Spending this connector blocks the claim's reimbursement payout. The decision to intervene is made outside the tool.

Each admin signs independently. Signature exchange, assembly, funding, and publication happen separately.

## Build and configuration

From the repository root:

```bash
cargo build --locked -p strata-bridge-admin-tool
```

Create `admin-tool.toml` in your working directory, replacing the placeholders:

```toml
network = "signet"
n_of_n_pubkey = "<N_OF_N_INTERNAL_PUBLIC_KEY>"
admin_pubkeys = ["<ADMIN_PUBLIC_KEY_0>", "<ADMIN_PUBLIC_KEY_1>", "<ADMIN_PUBLIC_KEY_2>"]
threshold = 2

[rpc]
url = "http://127.0.0.1:38332"
cookie_file = "/path/to/bitcoin/signet/.cookie"
```

Public keys are 32-byte x-only keys encoded as 64 hex characters. Use the untweaked N-of-N internal key and preserve the admin keys' script order. These settings must match the target claim, including when signing for an older claim.

The Bitcoin Core node must match `network` and have `txindex=1` to look up confirmed claims. For username/password authentication, replace `cookie_file` with `username` and `password` in `[rpc]`. Relative cookie paths resolve against the config file's directory.

Use `--config /path/to/admin-tool.toml` to select a different config file.

## 1. Inspect

```bash
./target/debug/admin-tool inspect \
  --claim-txid <CLAIM_TXID> \
  --unstaking-hash <UNSTAKING_HASH>
```

No signing key is needed. The command checks the node's network, reconstructs the connector, matches its script and amount against claim output 1, and checks that the output is unspent, including mempool spends.

It prints the claim outpoint, confirmation count, ordered admin keys, threshold, signing digest, and sighash mode. The unstaking hash is the public SHA-256 hashlock value; its secret preimage is not needed. The signing digest is the Bitcoin transaction signing hash, a separate value.

## 2. Sign

Supply an existing admin private key file containing 64 hex characters, with optional surrounding whitespace. The key must correspond to one of the configured admin public keys. This format is a private key, not a seed, mnemonic, or WIF; the tool does not generate keys or derive them from seeds.

```bash
./target/debug/admin-tool sign \
  --claim-txid <CLAIM_TXID> \
  --unstaking-hash <UNSTAKING_HASH> \
  --signer-file /path/to/admin-key \
  > signature.json
```

Signing repeats validation independently of any earlier inspection. The review summary goes to stderr; stdout contains JSON for sharing. The returned signature is verified before export.

Example output, with placeholders:

```json
{
  "claim_outpoint": "<CLAIM_TXID>:1",
  "admin_public_key": "<ADMIN_PUBLIC_KEY>",
  "admin_index": 0,
  "signing_digest": "<SIGNING_DIGEST>",
  "sighash_type": "0x82",
  "signature": "<128_HEX_CHARACTERS>82"
}
```

`admin_index` is zero-based. The signature is 65 bytes: a 64-byte Schnorr signature followed by the `0x82` sighash byte. Share the exported JSON through the separately agreed process; it is a signature record, not a transaction or PSBT.

## What the signature authorizes

Admins use `SIGHASH_NONE | SIGHASH_ANYONECANPAY` (`0x82`). The fixed signing template uses version 3, locktime zero, maximum input sequence, and no annex. A publisher can add funding inputs and choose outputs and fees afterward without requesting new admin signatures. Admins authorize the connector spend, not a final destination or fee.

The `AdminSigner` interface exposes public-key identification and digest signing. The current backend reads a private key file; future S2 or HSM backends can keep private material inside the backend.

Neither command funds or broadcasts a transaction. Both require a live RPC connection. They report confirmations but impose no minimum confirmation count; unspent status is checked at the time of the request.

## Validation

With `bitcoind` available on `PATH`:

```bash
cargo test --locked -p strata-bridge-admin-signing -p strata-bridge-admin-tool
```

The integration test runs the real CLI against a temporary Bitcoin Core regtest node, collects two independent admin signatures, adds funding separately, and mines the resulting spend.
