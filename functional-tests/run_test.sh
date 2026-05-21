#!/bin/bash
set -e
cd $(dirname $(realpath $0))
source env.bash

# Opt-in SP1 proving + external bitcoin config (see sp1-env.bash.sample).
# Present only when the user has set it up; absence = default runs.
if [ -f sp1-env.bash ]; then
    source sp1-env.bash
fi

# Set an explicit finite limit so bitcoind (and other
# subprocesses) inherit a sane value.
ulimit -n 10240

# Move to project root for cargo builds
pushd .. > /dev/null

# Configure build parameters based on environment
if [ $CI_COVERAGE ]; then
    echo "Building bridge node with coverage"
    COV_TARGET_DIR=$(realpath target)"/llvm-cov-target"
    mkdir -p $COV_TARGET_DIR
    export LLVM_PROFILE_FILE=$COV_TARGET_DIR"/strata-%p-%m.profraw"
    RUSTFLAGS="-Cinstrument-coverage"
    CARGO_ARGS="--target-dir $COV_TARGET_DIR"
    BIN_PATH=$COV_TARGET_DIR/debug
elif [ "$CARGO_DEBUG" = 0 ]; then
    CARGO_ARGS="--release"
    BIN_PATH=$(realpath target/release/)
else
    CARGO_ARGS=""
    BIN_PATH=$(realpath target/debug/)
fi

# Validate the external Bitcoin contract (network-extbtc env) before the slow build.
if [ "$BRIDGE_EXTERNAL_BITCOIN" = "1" ]; then
    : "${BITCOIN_RPC_URL:?set BITCOIN_RPC_URL=http://host:port for external bitcoin}"
    : "${BITCOIN_RPC_USER:?set BITCOIN_RPC_USER for external bitcoin}"
    : "${BITCOIN_RPC_PASSWORD:?set BITCOIN_RPC_PASSWORD for external bitcoin}"
    : "${BITCOIN_ZMQ_HOST:?set BITCOIN_ZMQ_HOST for external bitcoin}"
    : "${BITCOIN_ZMQ_HASHBLOCK_PORT:?set BITCOIN_ZMQ_HASHBLOCK_PORT for external bitcoin}"
    : "${BITCOIN_ZMQ_HASHTX_PORT:?set BITCOIN_ZMQ_HASHTX_PORT for external bitcoin}"
    : "${BITCOIN_ZMQ_RAWBLOCK_PORT:?set BITCOIN_ZMQ_RAWBLOCK_PORT for external bitcoin}"
    : "${BITCOIN_ZMQ_RAWTX_PORT:?set BITCOIN_ZMQ_RAWTX_PORT for external bitcoin}"
    : "${BITCOIN_ZMQ_SEQUENCE_PORT:?set BITCOIN_ZMQ_SEQUENCE_PORT for external bitcoin}"
    echo "External bitcoin mode: $BITCOIN_RPC_URL (zmq $BITCOIN_ZMQ_HOST), use env 'network-extbtc'"
fi

# Opt-in SP1 proving mode: build the guest ELF and enable the `sp1` feature on the bridge
# node. The mock-vs-real choice is driven entirely by SP1_PROVER, which every operator's
# bridge node inherits from this exported env:
#   - unset / "mock": fast mock proofs (default; no real proving)
#   - "cpu" / "cuda" / "network": real SP1 proving (much slower)
#
# With external bitcoin, generate asm-params from the live L1 (mining to genesis height)
# and bake them into the ELF so proofs verify against the actual chain; otherwise build
# with bundled stub params.
BRIDGE_FEATURES=""
if [ "$BRIDGE_PROOF_SP1" = "1" ]; then
    export SP1_PROVER="${SP1_PROVER:-mock}"
    if [ "$BRIDGE_EXTERNAL_BITCOIN" = "1" ]; then
        export BRIDGE_PROOF_SP1_PARAMS_DIR="$(realpath functional-tests)/_sp1_params"
        mkdir -p "$BRIDGE_PROOF_SP1_PARAMS_DIR"

        # Opt-in: real SP1 Groth16 ASM+Moho proving. Build the asm/moho guest ELFs at the
        # pinned asm rev, derive their Sp1Groth16 predicates, and (later) point the
        # asm-runner at the ELFs. Without this, the asm-runner signs native Schnorr
        # attestations and the vk files stay Bip340Schnorr.
        if [ "$BRIDGE_PROOF_SP1_ASM" = "1" ]; then
            ASM_REV=$(grep 'strata-asm-worker.*rev' Cargo.toml | sed 's/.*rev = "\([^"]*\)".*/\1/')
            [ -n "$ASM_REV" ] || { echo "ERROR: failed to extract asm rev from Cargo.toml" >&2; exit 1; }
            ASM_SRC="$(realpath functional-tests)/.asm-src"
            if [ "$(git -C "$ASM_SRC" rev-parse HEAD 2>/dev/null)" != "$ASM_REV" ]; then
                rm -rf "$ASM_SRC"
                git clone https://github.com/alpenlabs/asm "$ASM_SRC"
                git -C "$ASM_SRC" checkout "$ASM_REV"
            fi
            echo "Building ASM/Moho SP1 guest ELFs (asm rev $ASM_REV); this is slow"
            # The asm guest-builder compiles C deps for the riscv guest target; point AR at
            # the succinct toolchain's llvm-ar so cross-compilation finds a compatible archiver.
            SP1_AR="$(rustc +succinct --print sysroot)/lib/rustlib/$(rustc +succinct -vV | sed -n 's/^host: //p')/bin/llvm-ar"
            export AR="$SP1_AR"
            export AR_riscv64im_unknown_none_elf="$SP1_AR"
            ( cd "$ASM_SRC" && cargo build --release -p strata-asm-sp1-guest-builder )
            export BRIDGE_PROOF_ASM_ELF_PATH="$ASM_SRC/guest-builder/sp1/elfs/asm.elf"
            export BRIDGE_PROOF_MOHO_ELF_PATH="$ASM_SRC/guest-builder/sp1/elfs/moho.elf"

            # Derive the Sp1Groth16 predicates the bridge proof verifies against. These
            # match the asm-runner's own (shared sp1 6.2.0 / zkaleido v0.1-beta.2).
            cargo build --release -p strata-bridge-proof --features sp1 --bin sp1-predicate
            export BRIDGE_PROOF_SP1_ASM_PREDICATE="$(target/release/sp1-predicate "$BRIDGE_PROOF_ASM_ELF_PATH")"
            export BRIDGE_PROOF_SP1_MOHO_PREDICATE="$(target/release/sp1-predicate "$BRIDGE_PROOF_MOHO_ELF_PATH")"
            echo "ASM predicate:  $BRIDGE_PROOF_SP1_ASM_PREDICATE"
            echo "MOHO predicate: $BRIDGE_PROOF_SP1_MOHO_PREDICATE"
        fi

        echo "SP1 proving mode (SP1_PROVER=$SP1_PROVER): generating asm-params from external L1 $BITCOIN_RPC_URL"
        ( cd functional-tests && uv run python gen_sp1_params.py )
        export BRIDGE_PROOF_ASM_PARAMS_PATH="$BRIDGE_PROOF_SP1_PARAMS_DIR/asm-params.json"
        export BRIDGE_PROOF_ASM_VK_PATH="$BRIDGE_PROOF_SP1_PARAMS_DIR/asm-vk.json"
        export BRIDGE_PROOF_MOHO_VK_PATH="$BRIDGE_PROOF_SP1_PARAMS_DIR/moho-vk.json"
        cargo build --release -p strata-bridge-sp1-guest-builder
    else
        echo "SP1 proving mode (SP1_PROVER=$SP1_PROVER): building guest ELF with stub params (may take several minutes)"
        SKIP_PARAMS=1 cargo build --release -p strata-bridge-sp1-guest-builder
    fi
    BRIDGE_FEATURES="--features sp1"
    export BRIDGE_PROOF_SP1_ELF="$(realpath guest-builder/sp1/elfs/bridge-proof.elf)"
    echo "SP1 ELF: $BRIDGE_PROOF_SP1_ELF (SP1_PROVER=$SP1_PROVER)"
fi

# Build all required binaries (only strata-bridge and secret-service gets coverage instrumentation)
RUSTFLAGS="$RUSTFLAGS" cargo build --bin strata-bridge $CARGO_ARGS $BRIDGE_FEATURES
RUSTFLAGS="$RUSTFLAGS" cargo build -p secret-service --bin secret-service $CARGO_ARGS
cargo build --bin dev-cli $CARGO_ARGS

# Extract mosaic rev from Cargo.toml to avoid hardcoding
MOSAIC_REV=$(grep 'mosaic-rpc-api.*rev' Cargo.toml | sed 's/.*rev = "\([^"]*\)".*/\1/')
if [ -z "$MOSAIC_REV" ]; then
    echo "ERROR: failed to extract mosaic rev from Cargo.toml" >&2
    exit 1
fi

echo "installing mosaic (rev $MOSAIC_REV)"
mkdir -p functional-tests/_dd/.bin
CARGO_LOCAL_BIN=$(realpath "functional-tests/_dd/.bin")
export PATH="$CARGO_LOCAL_BIN/bin:$PATH"
RUSTFLAGS="" cargo install \
    --git https://github.com/alpenlabs/mosaic \
    --rev "$MOSAIC_REV" \
    --features=reduced-circuits \
    --root "$CARGO_LOCAL_BIN" \
    mosaic

# Extract asm rev from Cargo.toml to avoid hardcoding
ASM_REV=$(grep 'strata-asm-worker.*rev' Cargo.toml | sed 's/.*rev = "\([^"]*\)".*/\1/')
if [ -z "$ASM_REV" ]; then
    echo "ERROR: failed to extract asm rev from Cargo.toml" >&2
    exit 1
fi

# Real SP1 ASM/Moho proving needs the asm-runner's `sp1` feature (the Sp1 backend).
ASM_RUNNER_FEATURES=""
if [ "$BRIDGE_PROOF_SP1_ASM" = "1" ]; then
    ASM_RUNNER_FEATURES="--features sp1"
fi
echo "installing strata-asm-runner (rev $ASM_REV) $ASM_RUNNER_FEATURES"
RUSTFLAGS="" cargo install \
    --git https://github.com/alpenlabs/asm \
    --rev "$ASM_REV" \
    $ASM_RUNNER_FEATURES \
    --root "$CARGO_LOCAL_BIN" \
    strata-asm-runner

export PATH=$BIN_PATH:$PATH
popd > /dev/null
uv run python entry.py "$@"
