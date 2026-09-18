# `full_mosaic` tests

Tests that run against the **real g16 SP1-Groth16 verifier circuit** instead of the
bundled toy circuit. Manual-only: excluded from the default sweep via
`SKIP_GROUPS_BY_DEFAULT` in [`entry.py`](../../entry.py) and from the default CI matrix
in `.github/workflows/functional.yml`. There is no workflow for this group.

## Why the group exists

Nothing in Rust or in Bitcoin script ever verifies a counterproof against
`counterproof_predicate` — it appears only in the node's startup checks. Adjudication
happens entirely inside Mosaic's garbled circuit
(`crates/bridge-exec/src/graph/counterproof_nack.rs`: `evaluate_and_sign` returning
`None` means the fault secret was not extractable, so no NACK is possible).

Every other fn-test points Mosaic at `artifacts/mosaic_depositidx_ckt.v5c`, a 768 KB toy
circuit whose output is the least significant bit of the deposit-input wire — which the
bridge sets to the game index. So elsewhere in the suite the NACK fires iff the game index
is **even**, completely blind to the counterproof's contents. That is why
`tests/contested_payout/fn_publish_counterproof_nack.py` contests deposit index 1 and
`tests/slashing/fn_counterproof_ack.py` uses index 0.

Under the real circuit the verdict is the actual Groth16 check. Both tests here therefore
run at **deposit index 0** (game index 1, odd) — the index at which the toy circuit can
*never* produce a NACK — so the two opposite outcomes below are attributable to
counterproof validity and nothing else.

| Test | Counterproof | Expected outcome |
|---|---|---|
| `fn_valid_counterproof_acked.py` | genuine (operator posted a faulty bridge proof) | circuit accepts, no NACK possible, ACK after `nack_timelock`, operator slashed |
| `fn_invalid_counterproof_nackd.py` | forged (stale guest ELF) | circuit rejects, operator NACKs, `all_nackd`, contested payout, no slash |

Run one and not the other and you learn little; the pair is the experiment.

## Scope caveat

Cut-and-choose parameters are a **separate axis** from which circuit runs, selected by
`MOSAIC_CUT_AND_CHOOSE`: `reduced` builds mosaic with `--features=reduced-circuits`
(`N_CIRCUITS`/`N_OPEN_CIRCUITS` = 5/3, roughly 3-bit soundness), `full` uses 181/174 for
the 40-bit target.

Under `reduced`, these tests validate functional correctness of the counterproof verdict
only and must not be described as a security-parameter validation.

## Running

Needs `sp1-env.bash` (SP1 proving + external regtest bitcoind), with
`MOSAIC_CIRCUIT_MODE=full` and — for the invalid-counterproof test —
`BRIDGE_PROOF_SP1_STALE_ARTIFACTS=1`:

```bash
cp sp1-env.bash.sample sp1-env.bash   # then fill in NETWORK_PRIVATE_KEY and set the two vars
./run_test.sh -t tests/full_mosaic/fn_valid_counterproof_acked.py
```

`-t` or `-g full_mosaic` is required to bypass the default skip.

The g16 circuit generation runs in the background overlapping the cargo builds; its log is
at `_dd/.g16-runs/g16-gen.log`. Cost and disk requirements are in the main README's "Full
mosaic circuit mode" section. Delete `_dd/.g16-runs` afterwards to reclaim the space the
circuit retains.

Note the circuit is regenerated every run: it is bound at generation time to the
counterproof guest ELF's vkey, and that ELF is rebuilt from asm-params derived from the
live regtest chain. Pinning the ASM anchor across runs would make it cacheable and take
68 min off each run, but nothing does that today.

`SP1_PROVER=mock` does not work here: mock Groth16 proofs serialize to an empty byte
vector, so `verify_bridge_proof` returns false regardless of predicate and
`Sp1Groth16Proof::parse(...).expect(...)` panics in the counterproof duty.
