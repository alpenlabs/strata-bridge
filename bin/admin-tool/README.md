# admin-tool

Inspect and sign an authorization to spend a specific claim's payout connector (`claim_txid:1`). Spending this connector blocks the claim's reimbursement payout. The decision to intervene is made outside the tool.

Each admin signs independently. The `assemble` command verifies the shared signatures and constructs the admin witness. Signature exchange, funding, and publication happen separately.

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

Use exactly one signing input:

- `--signer-file`: an admin private key as 64 hex characters, with optional surrounding whitespace.
- `--operator-seed-file`: exactly 32 raw seed bytes, as used by the bridge secret service. The tool derives the operator's covenant key using the shared key-derivation library. Use this when an operator's covenant public key is also a configured admin key, as in staging.

Both inputs must resolve to one of the configured admin public keys. Hex-encoded seeds, mnemonics, and WIF are not accepted as operator seed files. The derived private key stays in memory; the tool does not export a key file.

```bash
./target/debug/admin-tool sign \
  --params /path/to/bridge/params.toml \
  --claim-txid <CLAIM_TXID> \
  --unstaking-hash <UNSTAKING_HASH> \
  --signer-file /path/to/admin-key \
  > alice.sig
```

For an operator seed file, replace `--signer-file` with:

```bash
  --operator-seed-file /path/to/operator-seed
```

Signing repeats validation independently of any earlier inspection. The review summary, signing digest, and admin public key go to stderr; stdout contains only the signature hex for sharing. The returned signature is verified before export.

Example output, with placeholders:

```text
<128_HEX_CHARACTERS>82
```

The signature is 65 bytes, encoded as 130 hex characters: a 64-byte Schnorr signature followed by the `0x82` sighash byte. Share it through the separately agreed process. No JSON wrapper, admin index, or public key needs to accompany it.

## 3. Assemble

Anyone with enough shared signatures can assemble the admin burn without loading a private key. For signatures saved as `alice.sig` and `bob.sig`:

```bash
./target/debug/admin-tool assemble \
  --params /path/to/bridge/params.toml \
  --claim-txid <CLAIM_TXID> \
  --unstaking-hash <UNSTAKING_HASH> \
  --signature "$(cat alice.sig)" \
  --signature "$(cat bob.sig)" \
  > admin-burn.hex
```

The command repeats claim validation and checks each signature against the signing digest and configured admin public keys to identify its signer. It requires at least the threshold number of distinct admins, rejects invalid signatures or repeated signers, and places signatures in the correct witness slots regardless of argument order. Errors identify the failing signature by its argument position, starting at 1. Signatures for another claim will fail verification. There is no cryptographic signature aggregation.

The review, included admin indices and public keys, and connector input weight go to stderr; stdout contains raw transaction hex. If more than the threshold number of valid signatures are supplied, the lowest admin indices are included. The transaction contains the signed connector input and a zero-value `OP_RETURN` output so an external wallet can fund it. No fee-funding input has been added.

For Bitcoin Core, pass the reported connector input weight to the funding wallet. For example, with a fee rate of 10 sat/vB:

```bash
bitcoin-cli fundrawtransaction '<TRANSACTION_HEX_FROM_ADMIN_BURN_FILE>' \
  '{"fee_rate":10,"minconf":1,"input_weights":[{"txid":"<CLAIM_TXID>","vout":1,"weight":<CONNECTOR_INPUT_WEIGHT>}]}'
```

Then sign the returned transaction using `signrawtransactionwithwallet` and publish it using `sendrawtransaction`. Adding funding inputs and changing outputs preserves the admin signatures. Preserve transaction version 3, locktime zero, and the connector input's outpoint, maximum sequence, and witness, with no annex.

## What the signature authorizes

Admins use `SIGHASH_NONE | SIGHASH_ANYONECANPAY` (`0x82`). The fixed signing template uses version 3, locktime zero, maximum input sequence, and no annex. A publisher can add funding inputs and choose outputs and fees afterward without requesting new admin signatures. Admins authorize the connector spend, not a final destination or fee.

That flexibility also allows funding substitution: an attacker can reuse the public admin signatures to replace a burn with an attacker-funded burn, then replace that transaction with a spend of only their funding input. The connector is left unspent. These replacements must satisfy [Bitcoin Core's fee and policy rules](https://github.com/bitcoin/bitcoin/blob/v30.0/doc/policy/mempool-replacements.md); maximum sequence does not prevent replacement of version 3 transactions.

The publisher can rebroadcast the original burn, but a delay could let the operator's reimbursement confirm first. Monitor confirmation and retry as needed; broadcasting alone does not complete the intervention. One eviction-and-recovery cycle has been demonstrated locally, but sustained-attack costs and reliability have not been measured.

The `AdminSigner` interface exposes public-key identification and digest signing. The current backend loads a private key file or derives a key from an operator seed file; future S2 or HSM backends can keep private material inside the backend.

None of the commands fund or broadcast a transaction. All require a live RPC connection. They report confirmations but impose no minimum confirmation count; unspent status is checked at the time of the request.

## Validation

With `bitcoind` available on `PATH`:

```bash
cargo test --locked -p strata-bridge-admin-tool
```

The integration test runs the real CLI against a temporary Bitcoin Core regtest node, collects admin signatures using both a private key file and an operator seed file, assembles the burn through the CLI, adds funding through an external Core wallet, and mines the resulting spend.
