# strata-bridge-sp1-guest-builder

Host crate that compiles the SP1 zkVM guest program for the bridge proof and exposes
the path to the resulting ELF.

## Build inputs (release builds only)

| Env var                            | Format     | Stub fallback under `SKIP_PARAMS=1` |
|------------------------------------|------------|-------------------------------------|
| `BRIDGE_PROOF_ASM_PARAMS_PATH`     | JSON file  | `stub/asm-params.json`              |
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

> **Warning.** `SKIP_PARAMS` builds use `PredicateKey::always_accept()` as the
> Moho VK. The proof still runs end-to-end but accepts any Moho witness — these
> builds are **not deployable**.

```bash
SKIP_PARAMS=1 cargo build -p strata-bridge-sp1-guest-builder --release
```

## Build flow

The build script is **active only in `--release`** (gated on `cfg(not(debug_assertions))`).
`dev`-profile builds are a no-op — `cargo build`, `cargo check`, and `cargo clippy` on
the host workspace run without invoking the SP1 toolchain or requiring the input JSONs.

In release the script:

1. Calls `strata_bridge_proof::load_genesis_from_paths` to derive a
   `BridgeProofGenesis` on the host and SSZ-encodes it to
   `guest-bridge-proof/build/genesis.bin`. The guest embeds this via
   `include_bytes!` and decodes it with `BridgeProofGenesis::from_ssz_bytes`.
2. Calls `sp1_build::build_program_with_args` to compile the SP1 guest ELF.
3. Copies the freshly compiled ELF from sp1-build's output directory to a stable
   cache path `guest-bridge-proof/build/guest-sp1-bridge-proof.elf`, which is
   what [`bridge_proof_elf_path()`](src/lib.rs) returns.

All `serde_json` parsing and `secp256k1` work runs here on the host. The guest's
only obligation is SSZ decoding.

### Skipping in release

`SP1_SKIP_PROGRAM_BUILD=true` and `cargo clippy --release` are detected and short-circuit
the entire pipeline — no genesis derivation, no ELF compile, no ELF migration. Any
cached ELF from a prior real build is left in place.

## Features

- `docker-build` — compile the guest inside Docker (via `BuildArgs { docker: true, .. }`)
  instead of the local SP1 toolchain. Useful for reproducible builds.

## Consumer API

```rust
use strata_bridge_sp1_guest_builder::bridge_proof_elf_path;

let elf_bytes = std::fs::read(bridge_proof_elf_path())
    .expect("guest ELF not built — run with `--release`");
```

Returns the absolute path to the cached ELF. The path is stable across builds; the file
itself only exists after a successful release build (and may be stale relative to
current source).
