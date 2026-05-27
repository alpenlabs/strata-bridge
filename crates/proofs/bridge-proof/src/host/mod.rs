//! Host-side bridge-proof construction.

mod backend;
mod config;
#[cfg(feature = "sp1")]
mod predicate;

pub use backend::{BridgeProofHost, ProofBackend};
pub use config::ProofBackendConfig;
#[cfg(feature = "sp1")]
pub use predicate::{
    sp1_groth16_predicate_key, sp1_groth16_predicate_string, sp1_groth16_predicate_string_from_key,
};
