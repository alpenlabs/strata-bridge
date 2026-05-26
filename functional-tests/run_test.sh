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

# Resolve a dependency's git rev pinned in Cargo.toml.
extract_cargo_rev() {
    local crate="$1"
    local rev
    rev=$(grep "${crate}.*rev" Cargo.toml | sed 's/.*rev = "\([^"]*\)".*/\1/')
    if [ -z "$rev" ]; then
        echo "ERROR: failed to extract ${crate} rev from Cargo.toml" >&2
        exit 1
    fi
    echo "$rev"
}

# Pin the asm rev once; sp1-setup.bash and the asm-runner install both consume it.
ASM_REV=$(extract_cargo_rev strata-asm-worker)

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

source functional-tests/sp1-setup.bash

# Build all required binaries (only strata-bridge and secret-service gets coverage instrumentation)
RUSTFLAGS="$RUSTFLAGS" cargo build --bin strata-bridge $CARGO_ARGS $BRIDGE_FEATURES
RUSTFLAGS="$RUSTFLAGS" cargo build -p secret-service --bin secret-service $CARGO_ARGS
cargo build --bin dev-cli $CARGO_ARGS

MOSAIC_REV=$(extract_cargo_rev mosaic-rpc-api)
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
