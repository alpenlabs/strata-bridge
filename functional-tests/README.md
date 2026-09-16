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
# Run all tests (skips groups marked SKIP_GROUPS_BY_DEFAULT — see note below)
./run_test.sh

# Run a specific test by path (always runs, even for skipped groups)
./run_test.sh -t tests/liveness/fn_network_test.py

# Run all tests in a group (subdirectory)
./run_test.sh -g liveness

# Run multiple groups
./run_test.sh -g contested_payout uncontested_payout

# Force-run an otherwise-skipped group by selecting it explicitly:
./run_test.sh -g proofs
```

> A few groups are deliberately skipped by the no-arg run because they're
> too expensive to drag into a default regression sweep. Today that's
> `proofs/` (the SP1 end-to-end proof tests) and `full_mosaic/` (the real
> Mosaic circuit tests). They still run when you pick them by path (`-t …`)
> or by group (`-g proofs`). The list lives in
> `SKIP_GROUPS_BY_DEFAULT` in [`entry.py`](entry.py).

## Running in SP1 proving mode

In SP1 proving mode the tests prove on SP1 and run against an externally-managed
regtest `bitcoind` (the `network-extbtc` environment).

1. Start a fresh regtest `bitcoind` with ZMQ enabled:

   ```bash
   TMPBTC=$(mktemp -d)
   bitcoind -regtest -server=1 -txindex=1 -listen=0 -datadir="$TMPBTC" \
     -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=18443 \
     -rpcuser=user -rpcpassword=password -fallbackfee=0.00001 -acceptnonstdtxn=0 \
     -zmqpubhashblock=tcp://127.0.0.1:28332 -zmqpubhashtx=tcp://127.0.0.1:28333 \
     -zmqpubrawblock=tcp://127.0.0.1:28334 -zmqpubrawtx=tcp://127.0.0.1:28335 \
     -zmqpubsequence=tcp://127.0.0.1:28336
   ```

2. Run an SP1-proving test against the external node:
   
   ```bash
   ./run_test.sh -t tests/proofs/fn_bridge_proof.py
   ```

   ```bash
   ./run_test.sh -t tests/proofs/fn_counterproof.py
   ```

   ```bash
   ./run_test.sh -t tests/proofs/fn_sp1_heavier_chain_counterproof.py
   ```

   `run_test.sh` mines the external L1 to the genesis height, generates `asm-params.json`
   from it, and bakes it into the guest ELF (no manual params step) so proofs verify
   against the actual chain.

   With `BRIDGE_PROOF_SP1_ASM=1` (default in the sample), `run_test.sh` also builds the
   ASM and Moho SP1 guest ELFs (cloning the asm repo at its pinned rev into `.asm-src/`)
   and runs the asm-runner's SP1 backend, so the ASM/Moho proofs are real SP1 Groth16
   proofs the bridge verifies via `Sp1Groth16` predicates. Set `BRIDGE_PROOF_SP1_ASM=0`
   to keep the ASM/Moho layer as native Schnorr attestations. Real Groth16 proving
   (and the extra ELF builds) only happens under `SP1_PROVER` ≠ `mock`.

### Full mosaic circuit mode

By default the mosaic nodes run the bundled 768 KB toy circuit
([`artifacts/mosaic_depositidx_ckt.v5c`](artifacts/mosaic_depositidx_ckt.v5c)), whose
output is just the least significant bit of the deposit-input wire — it never inspects
the counterproof at all. `MOSAIC_CIRCUIT_MODE=full` instead generates the REAL g16
SP1-Groth16 verifier circuit (134 GB `v5c.ckt`) from this run's counterproof vkey
with [alpenlabs/g16](https://github.com/alpenlabs/g16)'s `g16-pipeline` and points mosaic
at it (see [`g16-setup.bash`](g16-setup.bash)). The circuit must be regenerated every run
because the counterproof vkey bakes in per-run asm-params from the live regtest chain; the
generation runs in the background, overlapping the remaining builds.

**This selects the circuit artifact only.** Cut-and-choose parameters are an independent
axis, chosen with `MOSAIC_CUT_AND_CHOOSE`: `reduced` (default) builds mosaic with
`--features=reduced-circuits` for `N_CIRCUITS`/`N_OPEN_CIRCUITS` = 5/3, `full` uses
181/174 and the 40-bit soundness target. Disk scales with `N_EVAL_CIRCUITS = N - K` — the
tables the evaluator retains, 2 reduced vs 7 full — not with N, since the K opened
circuits are verified from their revealed seeds rather than stored. Against the real
circuit that is roughly 86 GB versus ~300 GB.

Requirements: SP1 proving mode set up as above (`sp1-env.bash`, external bitcoind,
`BRIDGE_PROOF_SP1=1`) and a large free mount (`G16_MIN_FREE_GB`, default 600).

Measured on a 16-core M-series Mac (g16 `v0.3.0-rc.2`, 2026-08-19): generation takes
**68 min** wall clock — `g16gen-generate` 17 min, `verify` 2 min, `ckt-lvl-prealloc`
48 min — and peaks at **~12 GB RSS**, well under the ~44 GB g16's README quotes. Disk is
the binding constraint, not RAM or CPU: the run's **high-water mark is ~400 GB**
(`g16.ckt` 175 GB + `fanout.cache` 44 GB + `v5c.ckt` 134 GB), pruned back to the 134 GB
`v5c.ckt` once generation finishes. Budget for the high-water mark, not the artifact.

Run locally:

```bash
MOSAIC_CIRCUIT_MODE=full ./run_test.sh -g full_mosaic
```

(or set `MOSAIC_CIRCUIT_MODE=full` in your `sp1-env.bash` to make it sticky). g16 is cloned
into `.g16-src/`, the circuit lands in `_dd/.g16-runs/` (gen log at
`_dd/.g16-runs/g16-gen.log`); delete `_dd/.g16-runs` afterwards to reclaim the space.

The tests that need this mode live in [`tests/full_mosaic/`](tests/full_mosaic/) — see
that directory's README. They are excluded from the default sweep and have no CI
workflow; run them by hand.

### SP1 env vars

Defaults come from [`sp1-env.bash.sample`](sp1-env.bash.sample). Override any of
them inline (e.g. `SP1_PROVER=cpu ./run_test.sh ...`) or by editing your local
`sp1-env.bash`.

| Variable | Default | Effect when overridden |
| --- | --- | --- |
| `BRIDGE_PROOF_SP1` | `1` | `0` disables SP1 proving entirely (native proofs, no guest ELF build). |
| `SP1_PROVER` | `network` | `mock` = fast stub proofs (no real proving); `cpu`/`cuda` = local real proving; `network` = remote proving via Succinct (requires `NETWORK_*`). |
| `SP1_PROOF_STRATEGY` | `reserved` | Succinct Network proof-request strategy (e.g. `reserved`, `hosted`, `auction`). Only used when `SP1_PROVER=network`. |
| `NETWORK_RPC_URL` | `https://rpc.production.succinct.xyz` | Point at a different Succinct prover network endpoint. |
| `NETWORK_PRIVATE_KEY` | _(unset)_ | **Required** for `SP1_PROVER=network`. Your Succinct prover account key; the network rejects requests without it. |
| `BRIDGE_PROOF_SP1_ASM` | `1` | `0` keeps the ASM/Moho layer as native Schnorr attestations (`Bip340Schnorr`) and skips the asm/moho guest ELF builds; `1` builds them and the bridge verifies real `Sp1Groth16` predicates. |
| `BRIDGE_DEV_MODE` | `1` | Skips the bridge startup consistency checks. Set `0` under `MOSAIC_CIRCUIT_MODE=full`, where the circuit is generated from the run's counterproof vkey so `verify_mosaic_vkey` passes on its merits (closes STR-3889). |
| `MOSAIC_CIRCUIT_MODE` | `mock` | `full` generates the real g16 Groth16 circuit for this run and points mosaic at it (see [Full mosaic circuit mode](#full-mosaic-circuit-mode)). Selects the circuit artifact only. |
| `MOSAIC_CUT_AND_CHOOSE` | `reduced` | Cut-and-choose parameters, independent of the circuit: `reduced` builds mosaic with `--features=reduced-circuits` (`N_CIRCUITS`/`N_OPEN_CIRCUITS` = 5/3), `full` omits it (181/174). Disk follows the `N - K` retained tables, 2 vs 7. |
| `G16_REF` | `G16_DEFAULT_REF` in `circuit-gen.yml` | alpenlabs/g16 ref to build `g16-pipeline` from (full mode only). |
| `G16_DIR` | _(unset)_ | Existing g16 checkout to use; otherwise cloned into `.g16-src/`. |
| `G16_RUNS_DIR` | `_dd/.g16-runs` | Where the g16 pipeline writes the circuit (needs a large mount). |
| `G16_MIN_FREE_GB` | `600` | Disk preflight threshold, covering the circuit plus the garbled tables and FoundationDB that share the mount. |
| `BRIDGE_PROOF_SP1_STALE_ARTIFACTS` | `0` | `1` builds a second, deliberately stale guest ELF pair from stub params, used by `tests/full_mosaic/fn_invalid_counterproof_nackd.py` to forge an invalid counterproof. |

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
