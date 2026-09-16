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

### `defcon1`

Publish a Defcon1 admin transaction activating the ASM safe harbour. Accepts one or more operator seeds as council signers (at least the council threshold's worth).

```bash
# Single signer (threshold-1 council)
dev-cli defcon1 \
  --seed <HEX_OPERATOR_SEED> \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password

# 2-of-3 council
dev-cli defcon1 \
  --seed <SEED_0> --signer-idx 0 \
  --seed <SEED_2> --signer-idx 2 \
  --seqno 1 \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password
```

### `safe-harbour-address-update`

Rotate the ASM safe harbour address. The ASM queues the update behind its configured confirmation depth and rejects it once Defcon1 is active, so it must be enacted before Defcon1.

```bash
dev-cli safe-harbour-address-update \
  --address tb1p<BECH32M_P2TR_ADDRESS> \
  --seed <SEED_0> --signer-idx 0 \
  --seed <SEED_1> --signer-idx 1 \
  --seqno 1 \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password
```

### `drt-takeback`

Reclaim a deposit request output through the depositor's takeback tapscript once the recovery delay has passed. Rebuilds the DRT taproot from the params and recovery secret and validates it against the on-chain output before signing.

The recovery secret is printed by `bridge-in` when the DRT is created (`recovery_secret = <hex>`).

```bash
dev-cli drt-takeback \
  --drt-txid <TXID> \
  --recovery-secret <HEX_SECRET_KEY> \
  --params ./params.toml \
  --btc-url http://127.0.0.1:18443/wallet/testwallet \
  --btc-user user \
  --btc-pass password
```

Optional flags: `--destination <ADDRESS>` (defaults to a fresh wallet address), `--fee-rate <SAT_PER_VB>` (default 10).

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
