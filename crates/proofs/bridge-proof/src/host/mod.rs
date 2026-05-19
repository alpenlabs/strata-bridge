//! Host-side bridge-proof construction.

mod backend;
mod config;

pub use backend::{BridgeProofHost, ProofBackend};
pub use config::ProofBackendConfig;
