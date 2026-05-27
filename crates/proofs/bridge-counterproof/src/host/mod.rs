//! Host-side bridge-counterproof construction.
//!
//! Thin wrapper over [`strata_bridge_proof_common::host`] that binds this crate's
//! native statement processor.

use anyhow::Result;
pub use strata_bridge_proof_common::host::{Host as BridgeCounterproofHost, ProofBackendConfig};

/// Builds the bridge-counterproof host from operator config.
pub async fn build_host(cfg: &ProofBackendConfig) -> Result<BridgeCounterproofHost> {
    strata_bridge_proof_common::host::build_host(
        "bridge-counterproof",
        cfg,
        crate::statements::process_counterproof,
    )
    .await
}
