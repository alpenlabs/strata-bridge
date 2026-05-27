//! Host-side bridge-proof construction.
//!
//! Thin wrapper over [`strata_bridge_proof_common::host`] that binds this crate's
//! native statement processor.

use anyhow::Result;
pub use strata_bridge_proof_common::host::{Host as BridgeProofHost, ProofBackendConfig};

#[cfg(feature = "sp1")]
mod predicate;
#[cfg(feature = "sp1")]
pub use predicate::{
    sp1_groth16_predicate_key, sp1_groth16_predicate_string, sp1_groth16_predicate_string_from_key,
};

/// Builds the bridge-proof host from operator config.
pub async fn build_host(cfg: &ProofBackendConfig) -> Result<BridgeProofHost> {
    strata_bridge_proof_common::host::build_host(
        "bridge-proof",
        cfg,
        crate::statements::process_bridge_proof,
    )
    .await
}
