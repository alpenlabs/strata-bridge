//! Host-side bridge-counterproof construction.

mod backend;
mod config;

pub use backend::{BridgeCounterproofHost, ProofBackend};
pub use config::ProofBackendConfig;
