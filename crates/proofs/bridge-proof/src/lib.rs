//! Bridge proof program: SSZ I/O types, [`zkaleido::ZkVmProgram`] impl, and
//! native/SP1 host construction.

// Imported as `_` so `--features sp1` (which switches `BridgeProofHost` to
// `SP1Host`) doesn't trip `unused_crate_dependencies`. Same trick as
// `strata-asm-runner`.
#[cfg(all(feature = "sp1", not(target_os = "zkvm")))]
use zkaleido_native_adapter as _;

pub mod errors;
#[cfg(not(target_os = "zkvm"))]
pub mod genesis;
pub mod host;
pub mod program;
#[cfg(not(target_os = "zkvm"))]
pub mod statements;
pub mod types;

pub use errors::BridgeProofVerificationError;
#[cfg(not(target_os = "zkvm"))]
pub use genesis::{BridgeProofGenesis, load_genesis};
pub use host::{BridgeProofHost, build_bridge_proof_host};
pub use program::BridgeProofProgram;
pub use moho_recursive_proof::MohoRecursiveOutput;
pub use types::{
    BridgeProofInput, BridgeProofOutput, MerkleProofB32, MohoState, OperatorClaimUnlock,
    RecursiveMohoProof,
};
