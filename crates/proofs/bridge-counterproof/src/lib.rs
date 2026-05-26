//! Bridge counterproof program: SSZ I/O types, [`zkaleido::ZkVmProgram`] impl,
//! and native/SP1 host construction.

// `zkaleido_native_adapter` is used by `host.rs` (default backend) and by tests; reference it
// under `feature = "sp1"` and under the zkvm guest target so the workspace's
// `unused_crate_dependencies` lint is satisfied in those configurations.
#[cfg(any(feature = "sp1", target_os = "zkvm"))]
use zkaleido_native_adapter as _;

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

        pub use genesis::load_genesis;
        pub use host::{BridgeCounterproofHost, build_bridge_counterproof_host};
        pub use program::CounterproofProgram;
    }
}
