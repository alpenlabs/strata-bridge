//! Bridge proof program: SSZ I/O types, [`zkaleido::ZkVmProgram`] impl, and
//! native/SP1 host construction.

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
        pub mod program;

        pub use genesis::{ASM_PARAMS_PATH_ENV, ASM_VK_PATH_ENV, MOHO_VK_PATH_ENV, load_genesis_from_env, load_genesis_from_paths};
        pub use program::BridgeProofProgram;
    }
}

#[cfg(not(target_os = "zkvm"))]
pub mod host;
#[cfg(not(target_os = "zkvm"))]
pub use host::{BridgeProofHost, ProofBackend, ProofBackendConfig};
