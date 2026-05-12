export RUST_LOG=${RUST_LOG:-debug,sled=info,hyper=warn,soketto=warn,jsonrpsee-server=warn,mio=warn,bitcoind-async-client::client=warn,trie=warn}
export NO_COLOR=${NO_COLOR:-1}
export RUST_BACKTRACE=${RUST_BACKTRACE:-1}
export LOG_LEVEL=${LOG_LEVEL:-info}

# Opt-in real SP1 proving. When 1, the python harness rebuilds strata-bridge
# with `--features sp1 --release` after asm-params are generated, asm-runner
# is installed with `--features sp1`, and ZKVM_MOCK is forced off.
export BRIDGE_SP1=${BRIDGE_SP1:-0}
if [ "$BRIDGE_SP1" = "1" ]; then
    export ZKVM_MOCK=0
else
    export ZKVM_MOCK=${ZKVM_MOCK:-1}
fi
