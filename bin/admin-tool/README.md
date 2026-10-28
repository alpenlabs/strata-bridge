# admin-tool

Inspect and sign an authorization to spend a specific claim's payout connector (`claim_txid:1`). Spending this connector blocks the claim's reimbursement payout. The decision to intervene is made outside the tool.

Each admin signs independently. Signature exchange, assembly, funding, and publication happen separately.

## Build and configuration

From the repository root:

```bash
cargo build --locked -p strata-bridge-admin-tool
```

Use the existing bridge `params.toml` for the network, ordered admin public keys, and threshold. The tool loads it through the bridge's shared params parser.

Create a separate `admin-tool.toml` for this tool's RPC connection and the target claim's N-of-N internal key:

```toml
n_of_n_pubkey = "<N_OF_N_INTERNAL_PUBLIC_KEY>"

[rpc]
url = "http://127.0.0.1:38332"
username = "username"
password = "password"
```

The internal key is a 32-byte x-only public key encoded as 64 hex characters, before any Taproot tweak. It remains explicit because an older claim may use different operator membership from the current operator schedule. The internal key and admin settings must match the target claim's connector.

The Bitcoin Core node must match the network in the bridge params and have `txindex=1` to look up confirmed claims. RPC uses username/password authentication and is configured only for this binary.

The default files are `params.toml` and `admin-tool.toml` in the working directory. Use `--params` and `--config` to select other paths.

## 1. Inspect

```bash
./target/debug/admin-tool inspect \
  --params /path/to/bridge/params.toml \
  --claim-txid <CLAIM_TXID> \
  --unstaking-hash <UNSTAKING_HASH>
```

No signing key is needed. The command checks the node's network, reconstructs the connector, matches its script and amount against claim output 1, and checks that the output is unspent, including mempool spends.

It prints the claim outpoint, confirmation count, ordered admin keys, threshold, signing digest, and sighash mode. The unstaking hash is the public SHA-256 hashlock value; its secret preimage is not needed. The signing digest is the Bitcoin transaction signing hash, a separate value.

## 2. Sign

Supply an existing admin private key file containing 64 hex characters, with optional surrounding whitespace. The key must correspond to one of the configured admin public keys. This format is a private key, not a seed, mnemonic, or WIF; the tool does not generate keys or derive them from seeds.

```bash
./target/debug/admin-tool sign \
  --params /path/to/bridge/params.toml \
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
