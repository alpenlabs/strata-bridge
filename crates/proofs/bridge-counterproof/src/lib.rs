//! Bridge counterproof program: SSZ I/O types, [`zkaleido::ZkVmProgram`] impl,
//! and native/SP1 host construction.

pub mod statements;
pub mod types;

pub use types::{
    BitcoinTxOut, BitcoinXOnlyPublicKey, BridgeCounterproofGenesis, CounterproofInput,
    CounterproofOutput, RawBitcoinTx,
};

cfg_if::cfg_if! {
    if #[cfg(not(target_os = "zkvm"))] {
        pub mod genesis;
        pub mod host;
        pub mod program;

        pub use genesis::{load_genesis_from_env, load_genesis_from_predicate};
        pub use host::{BridgeCounterproofHost, ProofBackendConfig, build_host};
        pub use program::CounterproofProgram;
    }
}
