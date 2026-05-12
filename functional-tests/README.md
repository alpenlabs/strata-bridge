# Strata Functional Tests

Tests will be added here when we have more functionality to test.

## Prerequisites

### `bitcoind`

Most tests depend upon `bitcoind` being available. The tests here execute
this binary and then, perform various tests.

```bash
# for macOS
brew install bitcoin
```

Note that in macOS, you may need to specifically add a firewall rule to allow incoming local `bitcoind` connections.

```bash
# for Linux (x86_64)
curl -fsSLO --proto "=https" --tlsv1.2 https://bitcoincore.org/bin/bitcoin-core-29.0/bitcoin-29.0-x86_64-linux-gnu.tar.gz
tar xzf bitcoin-29.0-x86_64-linux-gnu.tar.gz
sudo install -m 0755 -t /usr/local/bin bitcoin-29.0/bin/*
# remove the files, as we just copied it to /bin
rm -rf bitcoin-29.0 bitcoin-29.0-x86_64-linux-gnu.tar.gz
```

```bash
# check installed version
bitcoind --version
```

### `fdbserver` (FoundationDB)

The functional tests spawn FoundationDB server instances. You need both `fdbserver` and `fdbcli` binaries installed.

```bash
# for macOS (Apple Silicon)
curl -LO https://github.com/apple/foundationdb/releases/download/7.3.43/FoundationDB-7.3.43_arm64.pkg
sudo installer -pkg FoundationDB-7.3.43_arm64.pkg -target /

# for macOS (Intel)
curl -LO https://github.com/apple/foundationdb/releases/download/7.3.43/FoundationDB-7.3.43_x86_64.pkg
sudo installer -pkg FoundationDB-7.3.43_x86_64.pkg -target /
```

```bash
# for Linux (x86_64)
curl -fsSLO --proto "=https" --tlsv1.2 https://github.com/apple/foundationdb/releases/download/7.3.43/foundationdb-clients_7.3.43-1_amd64.deb
curl -fsSLO --proto "=https" --tlsv1.2 https://github.com/apple/foundationdb/releases/download/7.3.43/foundationdb-server_7.3.43-1_amd64.deb
sudo dpkg -i foundationdb-clients_7.3.43-1_amd64.deb
sudo dpkg -i foundationdb-server_7.3.43-1_amd64.deb
rm -f foundationdb-clients_7.3.43-1_amd64.deb foundationdb-server_7.3.43-1_amd64.deb
```

```bash
# check installed version
fdbcli --version
```

> **Note:** The functional tests share a single FDB server instance across all test
> environments. Each environment uses a unique root directory (e.g., `test-basic-a1b2c3d4`)
> within FDB's directory layer for isolation.

### `uv`

> [!NOTE]
> Make sure you have installed Python 3.10 or higher.

We use [`uv`](https://github.com/astral-sh/uv) for managing the test dependencies.

First, install `uv` following the instructions at <https://docs.astral.sh/uv/>.


Check, that `uv` is installed:

```bash
uv --version
```

Now you can run tests with:

```bash
uv run python entry.py
```


## Running tests
```bash
# Run all tests
./run_test.sh

# Run a specific test by path
./run_test.sh -t tests/liveness/fn_network_test.py

# Run all tests in a group (subdirectory)
./run_test.sh -g liveness

# Run multiple groups
./run_test.sh -g contested_payout uncontested_payout
```

## Running against an external bitcoind

By default the harness spawns its own `bitcoind`. To point it at a node you manage
(useful for long-running regtest setups or for real SP1 proving, below), set:

```bash
export BRIDGE_REMOTE_BTC_URL=http://127.0.0.1:18443   # must resolve to 127.0.0.1
export BRIDGE_REMOTE_BTC_USER=<rpcuser>
export BRIDGE_REMOTE_BTC_PASSWORD=<rpcpassword>
```

Start `bitcoind` with the harness's expected ZMQ ports:

```bash
bitcoind -regtest \
  -rpcuser=$BRIDGE_REMOTE_BTC_USER \
  -rpcpassword=$BRIDGE_REMOTE_BTC_PASSWORD \
  -rpcport=18443 \
  -zmqpubhashblock=tcp://0.0.0.0:28332 \
  -zmqpubhashtx=tcp://0.0.0.0:28333 \
  -zmqpubrawblock=tcp://0.0.0.0:28334 \
  -zmqpubrawtx=tcp://0.0.0.0:28335 \
  -zmqpubsequence=tcp://0.0.0.0:28336
```

The harness still calls `createwallet`, mines `initial_blocks`, funds operators
via `sendtoaddress`, and drives the auto-miner — only the bitcoind process
lifecycle moves to the user.

## Running with real SP1 proofs (`BRIDGE_SP1=1`)

By default the bridge proof runs in `ZKVM_MOCK=1` and produces a dummy receipt.
Set `BRIDGE_SP1=1` to produce a real Groth16 proof:

```bash
export BRIDGE_SP1=1
./run_test.sh -t fn_publish_counterproof_nack
```

What changes under `BRIDGE_SP1=1`:

- `strata-bridge` is rebuilt with `--features sp1 --release` **after** the
  harness writes `asm-params.json`, so the freshly-derived params are baked
  into the SP1 guest ELF (see `guest-builder/sp1/README.md`).
- `strata-asm-runner` is installed with `--features sp1`.
- `ZKVM_MOCK` is forced to `0`.
- Proof-phase wait timeouts are bumped to 1 hour.

Requirements:

- SP1 toolchain (`sp1up`).
- A running Docker daemon **or** `SP1_PROVER=network` + `NETWORK_PRIVATE_KEY` —
  required for Groth16 wrapping. Without one, the prove call dies at wrap time.
- Expect a single proof to take 10–30 min and ~32 GB RAM locally; the network
  prover is faster.

`BRIDGE_SP1=1` composes with `BRIDGE_REMOTE_BTC_URL` (set both for the typical
real-proving workflow against a long-running regtest).

## Running with code coverage

```bash
CI_COVERAGE=1 ./run_test.sh
```

Code coverage artifacts (`*.profraw` files) are generated in `target/llvm-cov-target/`.
Binaries and other build artifacts are generated in `target/llvm-cov-target/debug`.

#### Viewing test coverage (HTML)
Assuming `llvm` is installed.
Merge raw profiles:
```bash
llvm-profdata merge -sparse target/llvm-cov-target/*.profraw \
  -o target/llvm-cov-target/coverage.profdata
```

Generate HTML for each binary (bridge and s2)
```bash
PROFDATA=target/llvm-cov-target/coverage.profdata

llvm-cov show target/llvm-cov-target/debug/strata-bridge \
  -instr-profile="$PROFDATA" \
  -format=html \
  -output-dir=target/llvm-cov-target/coverage-html/strata-bridge

llvm-cov show target/llvm-cov-target/debug/secret-service \
  -instr-profile="$PROFDATA" \
  -format=html \
  -output-dir=target/llvm-cov-target/coverage-html/secret-service
```

View the html report
```bash
# bridge
open ./target/llvm-cov-target/coverage-html/strata-bridge/index.html

# s2
open ./target/llvm-cov-target/coverage-html/secret-service/index.html
```

## Debugging

### Service Logs
Logs are written in tests data directory:
```bash
🧪 functional-tests/
└── 📦 _dd/
    └── 🆔 <test_run_id>/            # Unique identifier for each test run
        ├── 🗄️ _shared_fdb/          # Shared FDB instance (one per test run)
        │   ├── 📄 service.log
        │   ├── 📄 fdb.cluster
        │   ├── 📁 data/             # FDB on-disk storage
        │   └── 📁 logs/             # FDB internal logs
        └── 🌍 <env_name>/           # Environment (e.g., "basic", "network")
            ├── ₿ bitcoin/
            │   └── 📄 service.log

            ├── 👷 <operator-i>/     # Operator instance (e.g., operator-0, operator-1)
            │   ├── 🌉 bridge_node/
            │   │   └── 📄 service.log
            │   └── 🔐 secret_service/
            │       └── 📄 service.log
            └── 🧾 logs/              # Logs per test module
                └── 📄 fn_rpc_test.log
```
