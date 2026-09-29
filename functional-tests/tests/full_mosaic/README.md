# `full_mosaic` tests

Two tests that run the counterproof game against the **real g16 SP1-Groth16 verifier
circuit** instead of the 768 KB toy circuit every other test uses. The toy circuit NACKs by
game-index parity and never looks at the counterproof; here the verdict is the actual
Groth16 check. Both tests use deposit index 0, where the toy circuit can never NACK, so the
opposite outcomes can only come from the real circuit.

| Test | Counterproof | Expected outcome |
|---|---|---|
| `fn_valid_counterproof_acked.py` | genuine | circuit refuses the NACK, ACK, operator slashed |
| `fn_invalid_counterproof_nackd.py` | forged (stale guest ELF) | circuit allows the NACK, contested payout, no slash |

Manual only: skipped by the default sweep and by CI.

## What you need

- Tools: `bitcoind` (tested with Core v30.2), `fdbserver`, `uv`, the Rust toolchain and the
  SP1 `succinct` toolchain (`sp1up`); see the main [README](../../README.md#prerequisites).
- A Succinct prover network key (`NETWORK_PRIVATE_KEY`). Bridge proofs, counterproofs and
  ASM/Moho proofs are real SP1 proofs; `SP1_PROVER=mock` does not work here.
- **~800 GB free disk** and **48 GB+ RAM** (64 GB tested; numbers below).
- An externally started regtest `bitcoind`, **fresh for every test** (step 2).

## Run, step by step

All commands run from `functional-tests/`.

**1. Configure once.** Copy the sample and set these values in `sp1-env.bash`:

```bash
cp sp1-env.bash.sample sp1-env.bash
```

```bash
export NETWORK_PRIVATE_KEY=<your-succinct-key>
export MOSAIC_CIRCUIT_MODE=full                  # the real circuit
export MOSAIC_CUT_AND_CHOOSE=full                # 181/174; `reduced` (5/3) is cheaper, see below
export BRIDGE_DEV_MODE=0                         # required: run_test.sh refuses full mode with 1
export BRIDGE_PROOF_SP1_STALE_ARTIFACTS=1        # required by the invalid test, harmless for the other
```

`sp1-env.bash` is gitignored. While it exists, every `./run_test.sh` uses these settings,
including runs of other groups; move it aside for normal runs.

**2. Start a fresh regtest bitcoind** in a separate terminal. Yes, it must be external:
this mode uses the `network-extbtc` env, and the ports must match `sp1-env.bash`.

```bash
BTC_DIR=$(mktemp -d)
```

```bash
bitcoind -regtest -server=1 -txindex=1 -listen=0 -datadir="$BTC_DIR" \
  -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=18443 \
  -rpcuser=user -rpcpassword=password -fallbackfee=0.00001 -acceptnonstdtxn=0 \
  -zmqpubhashblock=tcp://127.0.0.1:28332 -zmqpubhashtx=tcp://127.0.0.1:28333 \
  -zmqpubrawblock=tcp://127.0.0.1:28334 -zmqpubrawtx=tcp://127.0.0.1:28335 \
  -zmqpubsequence=tcp://127.0.0.1:28336
```

**3. Run ONE test.** On a laptop, keep it awake with `caffeinate`:

```bash
caffeinate -ims ./run_test.sh -t tests/full_mosaic/fn_valid_counterproof_acked.py
```

`run_test.sh` mines and funds the chain, builds the guest ELFs, generates the circuit in
the background (`_dd/.g16-runs/g16-gen.log`), then starts the test. Follow progress in
`_dd/<run-id>/logs/<test>.log`; the result is in `_dd/<run-id>/results.json`.

**4. Stop bitcoind and throw its chain away.**

```bash
bitcoin-cli -regtest -rpcuser=user -rpcpassword=password stop
```

```bash
rm -rf "$BTC_DIR"
```

**5. Run the other test** by repeating steps 2 to 4 with
`tests/full_mosaic/fn_invalid_counterproof_nackd.py`. One test per invocation and a fresh
chain each time: both tests need deposit index 0, so `entry.py` refuses `-g full_mosaic`
or two `-t`s.

**6. Reclaim the disk** (~755 GB per run). To keep the logs (~150 MB), copy them out first:

```bash
rsync -a --exclude garbling-tables --exclude /_shared_fdb/data _dd/<run-id>/ _dd/<run-id>-archive/
```

```bash
rm -rf _dd/<run-id> _dd/.g16-runs
```

## Time and space

Measured on an Apple M4 Max (16 cores, 64 GB RAM) with `MOSAIC_CUT_AND_CHOOSE=full`, four
runs between 2026-09-27 and 2026-09-29.

| Phase | Time |
|---|---|
| Guest ELF builds + mosaic/asm-runner installs | ~15 min first run, ~1 min cached (overlaps circuit generation) |
| Circuit generation (g16, background) | 43-49 min |
| Setup before the test starts | 44-55 min |
| Mosaic setup + staking | ~2h00m |
| Game, valid test (includes ~4m45s circuit evaluation) | ~7 min |
| Game, invalid test (includes ~17 min SP1 bridge proof) | ~23 min |
| **Total, valid test** | **~3h05m** |
| **Total, invalid test** | **~3h15m to 3h25m** |

| Resource | Peak |
|---|---|
| Circuit generation RSS | 13-42 GiB (varies run to run) |
| Mosaic node RSS | ~10-11 GiB each |
| Test FoundationDB RSS | ~4 GiB |
| Disk, during a run | **~760 GB**: 134 GB circuit + 2 x 308 GB garbling tables + 4 GB FDB; circuit generation alone peaks near 400 GB before pruning |
| Disk, left after a run | ~755 GB until step 6 |

`MOSAIC_CUT_AND_CHOOSE=reduced` retains 2 tables per operator instead of 7, so disk drops
to roughly 310 GB. Its timings have not been measured here, and it validates the verdict
only, not the 40-bit security parameters.

The circuit is regenerated on every run because it embeds the counterproof vkey, which is
rebuilt from asm-params anchored to the fresh chain. `MOSAIC_CIRCUIT_PATH` can reuse a
circuit only while that vkey is unchanged.

## If something goes wrong

- **Preflight refuses to start:** free disk is under `G16_MIN_FREE_GB` (800 by default
  under `full`, 600 under `reduced`).
- **`gen_asm_params_external.py` times out after 30 s:** bitcoind from step 2 is not running.
- **The valid test times out waiting for a verdict:** look for `evaluate_and_sign` in
  `_dd/<run-id>/_fn_valid_counterproof_acked/operator-0/bridge_node/service.log`.
- For error triage across the service logs, see the main README's Debugging section.
