# Mock Checkpoint CLI

A tool for creating and publishing mock checkpoints to Bitcoin for testing.
This enables user to create a checkpoint containing chainstate with arbitrary
deposits table. Store deposit entries in a json file and pass it to the cli.

## Usage

```bash
mock-checkpoint --sequencer-xpriv <MASTER_XPRIV> [OPTIONS]
```

## Arguments

- `--btc-url` - Bitcoin RPC endpoint (default: `http://localhost:18444/wallet/default`)
- `--btc-user` - RPC username (default: `user`)
- `--btc-pass` - RPC password (default: `password`)
- `--rollup-name` - Rollup name/magic bytes as it appears in L1 txs (default: `alpn`)
- `--fee-rate` - Fee rate in sats/vbyte (default: `100`)
- `--sequencer-address` - Sequencer address (default: `bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080`)
- `--network` - Bitcoin network: mainnet/testnet/signet/regtest (default: `regtest`)
- `--da-tag` - Data availability tag (default: `strata_da`)
- `--checkpoint-tag` - Checkpoint tag (default: `strata_ckpt`)
- `--sequencer-xpriv` - Sequencer private key (master xpriv from which the secret key is derived)
- `--deposit-entries` - Path to JSON file with deposit entries

## Example

```bash
export SEQUENCER_XPRIV=tprv8ezKDhpQHojBcUwXVZHBHBMg3QJQieAneQt9kkSMBoxdWdfBi1oBTiDev4J1ebeWH9hVV64fDeddyaLjMe7tjuS16QKPwykFAAiM66RcZWi
mock-checkpoint --deposit-entries deposit-entries.json
```
