export RUST_LOG=${RUST_LOG:-debug,sled=info,hyper=warn,soketto=warn,jsonrpsee-server=warn,mio=warn,bitcoind-async-client::client=warn,trie=warn}
export NO_COLOR=${NO_COLOR:-1}
export RUST_BACKTRACE=${RUST_BACKTRACE:-1}
export LOG_LEVEL=${LOG_LEVEL:-info}
export ZKVM_MOCK=${ZKVM_MOCK:-1}
