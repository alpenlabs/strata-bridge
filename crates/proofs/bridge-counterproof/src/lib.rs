//! Bridge counterproof program: SSZ I/O types, [`zkaleido::ZkVmProgram`] impl,
//! and native/SP1 host construction.

// Used only by `host.rs` when `sp1` is disabled; reference it here so the
// `unused_crate_dependencies` lint is satisfied under `--all-features --lib`.
#[cfg(feature = "sp1")]
use zkaleido_native_adapter as _;

#[cfg(not(target_os = "zkvm"))]
pub mod genesis;
pub mod host;
pub mod program;
#[cfg(not(target_os = "zkvm"))]
pub mod statements;
pub mod types;

#[cfg(not(target_os = "zkvm"))]
pub use genesis::{BridgeCounterproofGenesis, load_genesis};
pub use host::{BridgeCounterproofHost, build_bridge_counterproof_host};
pub use program::CounterproofProgram;
pub use types::{
    BitcoinTxOut, BitcoinXOnlyPublicKey, CounterproofInput, CounterproofMode, CounterproofOutput,
    HeavierChainProof, RawBitcoinTx,
};
