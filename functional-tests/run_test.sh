#!/bin/bash
set -e
cd $(dirname $(realpath $0))
source env.bash

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

# Build all required binaries (only strata-bridge and secret-service gets coverage instrumentation)
RUSTFLAGS="$RUSTFLAGS" cargo build --bin strata-bridge $CARGO_ARGS
RUSTFLAGS="$RUSTFLAGS" cargo build -p secret-service --bin secret-service $CARGO_ARGS
RUSTFLAGS="$RUSTFLAGS" cargo build --bin strata-asm-runner $CARGO_ARGS
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

export PATH=$BIN_PATH:$PATH
popd > /dev/null
uv run python entry.py "$@"
