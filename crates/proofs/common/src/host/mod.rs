//! Shared proof-host scaffolding reused by every per-program proof crate.

mod backend;
mod config;

pub use backend::{Host, build_host};
pub use config::ProofBackendConfig;
