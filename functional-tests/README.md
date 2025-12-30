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
````


## Running tests
```bash
# Run all tests
./run_tests.sh

# Run specific tests by name 
./run_test.sh fn_rpc_test


# Run specific tests by path 
./run_test.sh tests/fn_rpc_test.py
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

llvm-cov show target/llvm-cov-target/debug/alpen-bridge \
  -instr-profile="$PROFDATA" \
  -format=html \
  -output-dir=target/llvm-cov-target/coverage-html/alpen-bridge

llvm-cov show target/llvm-cov-target/debug/secret-service \
  -instr-profile="$PROFDATA" \
  -format=html \
  -output-dir=target/llvm-cov-target/coverage-html/secret-service
```

View the html report
```bash
# bridge
open ./target/llvm-cov-target/coverage-html/alpen-bridge/index.html

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
