//! Bridge proof program: SSZ I/O types, [`zkaleido::ZkVmProgram`] impl, and
//! native/SP1 host construction.

// `zkaleido_native_adapter` is used by `host.rs` (default backend) and by tests; reference it
// under `feature = "sp1"` and under the zkvm guest target so the workspace's
// `unused_crate_dependencies` lint is satisfied in those configurations.
#[cfg(any(feature = "sp1", target_os = "zkvm"))]
use zkaleido_native_adapter as _;

pub mod statements;
pub mod types;

pub use moho_recursive_proof::MohoRecursiveOutput;
pub use types::{
    BridgeProofGenesis, BridgeProofInput, BridgeProofOutput, MerkleProofB32, MohoState,
    OperatorClaimUnlock, RecursiveMohoProof,
};

cfg_if::cfg_if! {
    if #[cfg(not(target_os = "zkvm"))] {
        pub mod genesis;
        pub mod host;
        pub mod program;

        pub use genesis::{ASM_PARAMS_PATH_ENV, ASM_VK_PATH_ENV, MOHO_VK_PATH_ENV, load_genesis_from_env, load_genesis_from_paths};
        pub use host::{BridgeProofHost, build_bridge_proof_host};
        pub use program::BridgeProofProgram;
    }
}
