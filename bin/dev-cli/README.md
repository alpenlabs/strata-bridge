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
  --genesis-l1-height 101 \
  --ol-start-slot 0 \
  --ol-end-slot 1 \
  --network regtest
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
