# dev-cli

Strata Bridge CLI for dev environment.

## Commands

### `bridge-in`

Send a deposit request transaction on bitcoin.

```bash
dev-cli bridge-in \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password \
  --params ./params.toml \
  --ee-address 0x<EVM_ADDRESS>
```

### `create-and-publish-mock-checkpoint`

Create and broadcast a mock checkpoint via a taproot commit-reveal envelope.

```bash
dev-cli create-and-publish-mock-checkpoint \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password \
  --num-withdrawals 1 \
  --epoch 1 \
  --ol-start-slot 0 \
  --ol-end-slot 1 \
  --assignee-node-idx 0 \
  --params ./params.toml
```

The network, magic bytes, withdrawal amount (`protocol.deposit_amount`) and default genesis L1 height (`genesis_height`, override with `--genesis-l1-height`) come from the params file.

### `claim`

Post a claim transaction for a given deposit by reconstructing the game graph, signing the claim with the operator's watchtower key and broadcasting it.

```bash
dev-cli claim \
  --deposit-idx 0 \
  --operator-idx 0 \
  --bridge-node-url http://127.0.0.1:4781 \
  --seed <HEX_ENCODED_SEED> \
  --params ./params.toml \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password
```

### `contest`

Contest a claim transaction by signing and broadcasting a challenge via the game graph.

> **Note:** An operator cannot contest its own graph. The contester must be a different operator than the graph owner.

```bash
dev-cli contest \
  --deposit-idx 0 \
  --operator-idx 0 \
  --bridge-node-url http://127.0.0.1:4781 \
  --contester-node-idx 1 \
  --seed <HEX_ENCODED_SEED> \
  --params ./params.toml \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password
```

### `wallet-birthday`

Compute the `[operator_wallet]` bootstrap checkpoint for a bridge node: the block holding the oldest output either operator wallet still has unspent, found with one `scantxoutset` over both addresses on your own node. The addresses are the `general_wallet_address` and `reserved_wallet_address` printed by `derive-keys`, or the `general wallet address:` / `reserved wallet address:` lines the node logs at startup.

```bash
dev-cli wallet-birthday \
  --general-address <GENERAL_WALLET_ADDRESS> \
  --reserved-address <RESERVED_WALLET_ADDRESS> \
  --explorer-url https://mempool.space/api \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password
```

The output is the `[operator_wallet]` table to paste into the node config. `--explorer-url` is optional: when given, the command fails if `<url>/block-height/<height>` (a mempool/esplora API; use `https://mempool.space/signet/api` on signet) disagrees with the node, which is what catches a node following another chain. Passing `--expect-height`, and optionally `--expect-block-hash`, switches to verify mode: it prints a one-line verdict and exits non-zero unless the configured height is at or below the birthday and the hash is the node's block at that height. The scan takes minutes on mainnet: `--rpc-timeout` bounds it in seconds (default 3600), and run it against the node's RPC port directly, since a reverse proxy's idle timeout can cut it off.
