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
elif [ "$BRIDGE_SP1" = "1" ] || [ "$CARGO_DEBUG" = 0 ]; then
    # SP1 mode requires --release (guest builder is no-op under debug).
    CARGO_ARGS="--release"
    BIN_PATH=$(realpath target/release/)
else
    CARGO_ARGS=""
    BIN_PATH=$(realpath target/debug/)
fi

# Build required binaries. Under BRIDGE_SP1=1 the strata-bridge build is
# deferred until the python harness has generated asm-params.json — the
# guest-builder bakes those params at compile time.
if [ "$BRIDGE_SP1" = "1" ]; then
    echo "BRIDGE_SP1=1: deferring strata-bridge build until asm-params are generated"
else
    RUSTFLAGS="$RUSTFLAGS" cargo build --bin strata-bridge $CARGO_ARGS
fi
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

echo "installing strata-asm-runner (rev $ASM_REV)"
ASM_FEATURES=""
if [ "$BRIDGE_SP1" = "1" ]; then
    ASM_FEATURES="--features sp1"
    # Point AR at the SP1 toolchain's llvm-ar so secp256k1-sys' build.rs
    # can produce a static lib for riscv64im-succinct-zkvm-elf.
    SP1_AR="$(rustc +succinct --print sysroot)/lib/rustlib/$(rustc +succinct -vV | sed -n 's/^host: //p')/bin/llvm-ar"
    export AR="$SP1_AR"
    export AR_riscv64im_unknown_none_elf="$SP1_AR"
fi
RUSTFLAGS="" cargo install \
    --git https://github.com/alpenlabs/asm \
    --rev "$ASM_REV" \
    $ASM_FEATURES \
    --root "$CARGO_LOCAL_BIN" \
    strata-asm-runner

export PATH=$BIN_PATH:$PATH
popd > /dev/null
uv run python entry.py "$@"
