#!/bin/bash
set -e
cd $(dirname $(realpath $0))
source env.bash

# Opt-in SP1 proving + external bitcoin config (see sp1-env.bash.sample).
# Present only when the user has set it up; absence = default runs.
if [ -f sp1-env.bash ]; then
    source sp1-env.bash
fi

# Mosaic circuit mode: mock (default; bundled 768 KB reduced circuit) or full
# (generate the real g16 Groth16 circuit for this run — see g16-setup.bash).
export MOSAIC_CIRCUIT_MODE="${MOSAIC_CIRCUIT_MODE:-mock}"
case "$MOSAIC_CIRCUIT_MODE" in
    mock|full) ;;
    *)
        echo "ERROR: MOSAIC_CIRCUIT_MODE must be 'mock' or 'full' (got '$MOSAIC_CIRCUIT_MODE')" >&2
        exit 1
        ;;
esac

# Set an explicit finite limit so bitcoind (and other
# subprocesses) inherit a sane value.
ulimit -n 10240

# Move to project root for cargo builds
pushd .. > /dev/null

# Resolve a dependency's git ref pinned in Cargo.toml.
extract_cargo_git_ref() {
    local crate="$1"
    local dep_line
    dep_line=$(grep -E "^[[:space:]]*${crate}[[:space:]]*=" Cargo.toml | head -n 1)
    if [[ "$dep_line" =~ (rev|tag)[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
        return
    fi
    echo "ERROR: failed to extract ${crate} git ref from Cargo.toml" >&2
    exit 1
}

# Pin the asm ref once; sp1-setup.bash and the asm-runner install both consume it.
read -r ASM_REF_TYPE ASM_REF < <(extract_cargo_git_ref strata-asm-worker)

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
    mkdir -p target/release
    BIN_PATH=$(realpath target/release/)
else
    CARGO_ARGS=""
    mkdir -p target/debug
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

source functional-tests/sp1-setup.bash

# Full circuit mode: kick off the g16 circuit generation in the background right
# after the guest build (the circuit embeds this run's counterproof vkey), so it
# overlaps the remaining builds and installs; the wait sits just before entry.py.
source functional-tests/g16-setup.bash
if [ "$MOSAIC_CIRCUIT_MODE" = "full" ]; then
    if [ "$BRIDGE_PROOF_SP1" != "1" ]; then
        echo "ERROR: MOSAIC_CIRCUIT_MODE=full requires BRIDGE_PROOF_SP1=1 (the circuit embeds this run's counterproof vkey)" >&2
        exit 1
    fi
    trap g16_cleanup_on_exit EXIT
    g16_start_generation
fi

# Build all required binaries (only strata-bridge and secret-service gets coverage instrumentation)
RUSTFLAGS="$RUSTFLAGS" cargo build --bin strata-bridge $CARGO_ARGS $BRIDGE_FEATURES
RUSTFLAGS="$RUSTFLAGS" cargo build -p secret-service --bin secret-service $CARGO_ARGS
cargo build --bin dev-cli $CARGO_ARGS

read -r MOSAIC_REF_TYPE MOSAIC_REF < <(extract_cargo_git_ref mosaic-rpc-api)
# Full circuit mode needs the full-featured garbling backend; mock uses the
# reduced one. cargo tracks the feature set in .crates2.json, so flipping modes
# reinstalls automatically.
MOSAIC_FEATURES="--features=reduced-circuits"
if [ "$MOSAIC_CIRCUIT_MODE" = "full" ]; then
    MOSAIC_FEATURES=""
fi
echo "installing mosaic ($MOSAIC_REF_TYPE $MOSAIC_REF) [circuit: $MOSAIC_CIRCUIT_MODE]"
mkdir -p functional-tests/_dd/.bin
CARGO_LOCAL_BIN=$(realpath "functional-tests/_dd/.bin")
export PATH="$CARGO_LOCAL_BIN/bin:$PATH"
RUSTFLAGS="" cargo install \
    --locked \
    --git https://github.com/alpenlabs/mosaic \
    "--$MOSAIC_REF_TYPE" "$MOSAIC_REF" \
    $MOSAIC_FEATURES \
    --root "$CARGO_LOCAL_BIN" \
    mosaic

# Real SP1 ASM/Moho proving needs the asm-runner's `sp1` feature (the Sp1 backend).
ASM_RUNNER_FEATURES=""
if [ "$BRIDGE_PROOF_SP1_ASM" = "1" ]; then
    ASM_RUNNER_FEATURES="--features sp1"
fi
echo "installing strata-asm-runner ($ASM_REF_TYPE $ASM_REF) $ASM_RUNNER_FEATURES"
RUSTFLAGS="" cargo install \
    --locked \
    --git https://github.com/alpenlabs/asm \
    "--$ASM_REF_TYPE" "$ASM_REF" \
    $ASM_RUNNER_FEATURES \
    --root "$CARGO_LOCAL_BIN" \
    strata-asm-runner

export PATH=$BIN_PATH:$PATH
popd > /dev/null

# Block on the backgrounded circuit generation; exports MOSAIC_CIRCUIT_PATH for
# the mosaic node configs, or exits non-zero so entry.py never starts against a
# missing circuit.
if [ "$MOSAIC_CIRCUIT_MODE" = "full" ]; then
    g16_wait_for_circuit
fi
uv run python entry.py "$@"
