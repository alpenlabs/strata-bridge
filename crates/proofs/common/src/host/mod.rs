//! Shared proof-host scaffolding reused by every per-program proof crate.

mod backend;
mod config;

#[cfg(feature = "sp1")]
mod predicate;

pub use backend::{Host, build_host};
pub use config::ProofBackendConfig;
#[cfg(feature = "sp1")]
pub use predicate::{
    sp1_groth16_predicate_key, sp1_groth16_predicate_string, sp1_groth16_predicate_string_from_key,
    sp1_program_vkey_hash,
};
