# Mock Checkpoint CLI

A tool for creating and publishing mock checkpoints to Bitcoin for testing.
This enables user to create a checkpoint containing chainstate with arbitrary
deposits table. Store deposit entries in a json file and pass it to the cli.

## Usage

```bash
mock-checkpoint --sequencer-private-key <HEX_KEY> [OPTIONS]
```

## Arguments

- `--bitcoin-url` - Bitcoin RPC endpoint (default: `http://localhost:18444`)
- `--bitcoin-username` - RPC username (default: `rpcuser`)
- `--bitcoin-password` - RPC password (default: `rpcpassword`)
- `--fee-rate` - Fee rate in sats/vbyte (default: `100`)
- `--sequencer-address` - Sequencer address (default: `bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080`)
- `--network` - Bitcoin network: mainnet/testnet/signet/regtest (default: `regtest`)
- `--da-tag` - Data availability tag (default: `alpn_da`)
- `--checkpoint-tag` - Checkpoint tag (default: `alpn_ckpt`)
- `--sequencer-private-key` - Sequencer private key (32-byte hex string, required)
- `--deposit-entries` - Path to JSON file with deposit entries (optional)

## Example

```bash
export SEQUENCER_PRIVATE_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
mock-checkpoint
```
