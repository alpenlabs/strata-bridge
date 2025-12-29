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

You can run all tests:

```bash
./run_test.sh
```

You also can run a specific test:

```bash
./run_test.sh fn_rpc_test
```

## Running with code coverage

```bash
CI_COVERAGE=1 ./run_test.sh
```

Code coverage artifacts (`*.profraw` files) are generated in `target/llvm-cov-target/`.
Binaries and other build artifacts are generated in `target/llvm-cov-target/debug`.
