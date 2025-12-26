#!/bin/bash
set -e

cd $(dirname $(realpath $0))

source env.bash

# also figure out the bins path
pushd .. > /dev/null

if [ $CI_COVERAGE ]; then
    echo "Building bridge node with coverage"
    COV_TARGET_DIR=$(realpath ../target)"/llvm-cov-target"
    mkdir -p $COV_TARGET_DIR
    export LLVM_PROFILE_FILE=$COV_TARGET_DIR"/strata-%p-%m.profraw"
    RUSTFLAGS="-Cinstrument-coverage" cargo build --bin alpen-bridge --target-dir "$COV_TARGET_DIR"
    RUSTFLAGS="-Cinstrument-coverage" cargo build -p secret-service --bin secret-service --target-dir "$COV_TARGET_DIR"
    RUSTFLAGS="-Cinstrument-coverage" cargo build --bin dev-cli --target-dir "$COV_TARGET_DIR"
    export PATH=$COV_TARGET_DIR/debug:$PATH
else
    if [ "$CARGO_DEBUG" = 0 ]; then
        cargo build --bin alpen-bridge --release
        cargo build -p secret-service --bin secret-service --release
        cargo build --bin dev-cli --release
        export PATH=$(realpath target/release/):$PATH
    else
        cargo build --bin alpen-bridge
        cargo build -p secret-service --bin secret-service
        cargo build --bin dev-cli
        export PATH=$(realpath target/debug/):$PATH
    fi
fi
popd > /dev/null

uv run python entry.py "$@"
