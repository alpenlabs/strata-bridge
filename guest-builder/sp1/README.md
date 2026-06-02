# strata-bridge-sp1-guest-builder

Host crate that compiles the SP1 zkVM guest program for the bridge proof and exposes
the path to the resulting ELF.

## Build inputs (release builds only)

| Env var                            | Format     | Stub fallback under `SKIP_PARAMS=1` |
|------------------------------------|------------|-------------------------------------|
| `BRIDGE_PROOF_ASM_PARAMS_PATH`     | JSON file  | `stub/asm-params.json`              |
| `BRIDGE_PROOF_ASM_VK_PATH`         | JSON file  | `stub/asm-vk.json`                  |
| `BRIDGE_PROOF_MOHO_VK_PATH`        | JSON file  | `stub/moho-vk.json`                 |

If either env var is unset on a release build and `SKIP_PARAMS` is not set, the build
script panics with a message naming the missing variable and the `SKIP_PARAMS=1`
escape hatch.

### `moho-vk.json` format

A single JSON string in the `PredicateKey` human-readable serde form:

```json
"AlwaysAccept"
```

```json
"Bip340Schnorr:<hex of the 32-byte x-only public key>"
```

```json
"Sp1Groth16:<hex of the verifying key bytes>"
```

## `SKIP_PARAMS` for CI

`SKIP_PARAMS=1` redirects both inputs to the bundled `stub/` files so CI can
verify the program **compiles** without provisioning real inputs.

> **Warning.** `SKIP_PARAMS` builds embeds a stale Moho VK — **not deployable**.

```bash
SKIP_PARAMS=1 cargo build -p strata-bridge-sp1-guest-builder --release --features build-elf
```

Or via the `.justfile` recipe:

```bash
just build-stub-elf
```

## Build flow

The guest ELF is built only when you pass **`--release --features build-elf`**.
Everything else (`cargo build`, `cargo check`, `cargo clippy`, plain `--release`)
is a no-op for this crate and does not pull in the SP1 toolchain.

In release the script:

1. Calls `strata_bridge_proof::load_genesis_from_paths` to derive a
   `BridgeProofGenesis` on the host and SSZ-encodes it to
   `guest-bridge-proof/build/genesis.bin`. The guest embeds this via
   `include_bytes!` and decodes it with `BridgeProofGenesis::from_ssz_bytes`.
2. Calls `sp1_build::build_program_with_args` with `output_directory` and
   `elf_name` set so the compiled ELF lands directly at
   `<crate>/elfs/bridge-proof.elf`, which is what
   [`BRIDGE_PROOF_ELF_PATH`](src/lib.rs) points at.

All `serde_json` parsing and `secp256k1` work runs here on the host. The guest's
only obligation is SSZ decoding.

### Skipping in release

`SP1_SKIP_PROGRAM_BUILD=true` and `cargo clippy --release` are detected and short-circuit
the entire pipeline — no genesis derivation, no ELF compile. Any cached ELF from
a prior real build is left in `elfs/`.

## Features

- `build-elf` — opt-in: actually compile the SP1 guest ELF in release builds.
  Required to bring in the SP1 host stack (`sp1-build`, `ssz`,
  `strata-bridge-proof/sp1`) as build-dependencies. Without it, `build.rs` is a
  no-op even in `--release` and plain workspace builds (`cargo build
  --workspace`) do not pull the SP1 toolchain.
- `docker-build` — compile the guest inside Docker (via `BuildArgs { docker: true, .. }`)
  instead of the local SP1 toolchain. Useful for reproducible builds. Implies
  `build-elf`.

## Consumer API

```rust
use strata_bridge_sp1_guest_builder::BRIDGE_PROOF_ELF_PATH;

let elf_bytes = std::fs::read(BRIDGE_PROOF_ELF_PATH)
    .expect("guest ELF not built — run with `--release`");
```

`BRIDGE_PROOF_ELF_PATH` is a `&'static str` baked at compile time of this crate
(`<crate>/elfs/bridge-proof.elf`). The path is stable across builds; the file
itself only exists after a successful release build (and may be stale relative
to current source).
