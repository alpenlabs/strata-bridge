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
