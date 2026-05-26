//! Bridge-proof host construction.
//!
//! Bundles the runtime host enum and the constructor that turns a
//! [`ProofBackendConfig`] into a ready-to-use [`BridgeProofHost`].

#[cfg(feature = "sp1")]
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::info;
use zkaleido_native_adapter::NativeHost;
#[cfg(feature = "sp1")]
use zkaleido_sp1_host::SP1Host;

use crate::host::config::ProofBackendConfig;

/// Runtime selection of the host used to generate bridge proofs.
#[derive(Clone, Debug)]
pub enum BridgeProofHost {
    /// Native in-process host.
    Native(NativeHost),
    /// SP1 host loaded from a compiled guest ELF.
    #[cfg(feature = "sp1")]
    Sp1(Box<SP1Host>),
}

/// Resolved bridge-proof host for the active backend.
#[derive(Debug)]
pub struct ProofBackend {
    /// The host used to produce bridge proofs.
    pub bridge_proof_host: BridgeProofHost,
}

impl ProofBackend {
    /// Builds the proof backend from operator config.
    pub async fn new(cfg: &ProofBackendConfig) -> Result<Self> {
        let bridge_proof_host = build_bridge_proof_host(cfg)
            .await
            .context("failed to build bridge-proof host")?;
        Ok(Self { bridge_proof_host })
    }
}

async fn build_bridge_proof_host(cfg: &ProofBackendConfig) -> Result<BridgeProofHost> {
    match cfg {
        #[cfg(feature = "sp1")]
        ProofBackendConfig::Sp1 { elf_path } => {
            info!(elf_path = %elf_path.display(), "sp1 host: reading guest ELF");
            let read_started = Instant::now();
            let elf = std::fs::read(elf_path).with_context(|| {
                format!(
                    "failed to read bridge-proof guest ELF at {}",
                    elf_path.display()
                )
            })?;
            info!(
                elf_bytes = elf.len(),
                elapsed_ms = read_started.elapsed().as_millis() as u64,
                "sp1 host: ELF read complete; initializing SP1Host",
            );
            let init_started = Instant::now();
            let host = SP1Host::init(&elf).await;
            info!(
                elapsed_ms = init_started.elapsed().as_millis() as u64,
                "sp1 host: SP1Host::init complete",
            );
            Ok(BridgeProofHost::Sp1(Box::new(host)))
        }
        ProofBackendConfig::Native {
            schnorr_signing_key,
        } => {
            use crate::statements::process_bridge_proof;

            info!("native host: initializing");
            Ok(BridgeProofHost::Native(NativeHost::new(
                schnorr_signing_key.clone(),
                process_bridge_proof,
            )))
        }
    }
}
