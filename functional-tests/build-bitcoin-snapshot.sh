#!/bin/bash
set -euo pipefail
cd "$(dirname "$(realpath "$0")")"
source env.bash

# bitcoind requires a sane file-descriptor limit; matches run_test.sh.
ulimit -n 10240

exec uv run python -m utils.bitcoin_snapshot.build "$@"
