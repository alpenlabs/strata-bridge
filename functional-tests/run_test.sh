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

# check if mosaic is in PATH, else install from source
if ! command -v mosaic &> /dev/null; then
    echo "mosaic not found, installing..."
    mkdir -p functional-tests/.bin
    CARGO_LOCAL_BIN=$(realpath "functional-tests/.bin")
    export PATH="$CARGO_LOCAL_BIN/bin:$PATH"
    RUSTFLAGS="" cargo install \
        --git https://github.com/alpenlabs/mosaic \
        --rev 0be9fbfdea678fe5fc98f35266c5c1b73f9dcebc \
        --bin mosaic \
        --features=reduced-circuits \
        --root "$CARGO_LOCAL_BIN" \
        mosaic
fi

export PATH=$BIN_PATH:$PATH
popd > /dev/null
uv run python entry.py "$@"
