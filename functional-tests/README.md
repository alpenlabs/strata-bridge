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
./run_test.sh -t tests/bridge/fn_rpc_test.py

# Run all tests in a group (subdirectory)
./run_test.sh -g asm

# Run multiple groups
./run_test.sh -g asm payout
```

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
