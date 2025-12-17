#!/bin/bash
set -e

cd $(dirname $(realpath $0))

source env.bash

# also figure out the bins path
pushd .. > /dev/null

if [ "$CARGO_DEBUG" = 0 ]; then
    cargo build --bin alpen-bridge --release
    cargo build --bin dev-cli --release
    cargo build -p secret-service --bin secret-service --release
	export PATH=$(realpath target/release/):$PATH
else
    cargo build --bin alpen-bridge
    cargo build -p secret-service --bin secret-service
    cargo build --bin dev-cli
	export PATH=$(realpath target/debug/):$PATH
fi
popd > /dev/null

uv run python entry.py "$@"
