#!/bin/bash
set -e

cd $(dirname $(realpath $0))

source env.bash

# also figure out the bins path
pushd .. > /dev/null

# build the bin
# cargo build

if [ "$CARGO_DEBUG" = 0 ]; then
	export PATH=$(realpath target/release/):$PATH
else
	export PATH=$(realpath target/debug/):$PATH
fi
popd > /dev/null

uv run python entry.py "$@"
