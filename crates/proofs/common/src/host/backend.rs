//! Shared proof-host construction.
//!
//! Defines the runtime host enum and the generic constructor that turns a
//! [`ProofBackendConfig`] into a ready-to-use [`Host`], parameterized over the
//! per-proof native statement-processing function.

#[cfg(feature = "sp1")]
use std::time::Instant;

#[cfg(feature = "sp1")]
use anyhow::Context;
use anyhow::Result;
use tracing::info;
use zkaleido_native_adapter::{NativeHost, NativeMachine};
#[cfg(feature = "sp1")]
use zkaleido_sp1_host::SP1Host;

use crate::host::config::ProofBackendConfig;

/// Runtime selection of the host used to generate proofs.
#[derive(Clone, Debug)]
pub enum Host {
    /// Native in-process host.
    Native(NativeHost),
    /// SP1 host loaded from a compiled guest ELF.
    #[cfg(feature = "sp1")]
    Sp1(Box<SP1Host>),
}

/// Builds a [`Host`] from operator config, binding the given native statement processor.
///
/// `proof_name` is threaded into every log field so per-proof signal is preserved
/// despite the shared body.
pub async fn build_host<F>(
    proof_name: &'static str,
    cfg: &ProofBackendConfig,
    native_processor: F,
) -> Result<Host>
where
    F: Fn(&NativeMachine) + Send + Sync + 'static,
{
    match cfg {
        #[cfg(feature = "sp1")]
        ProofBackendConfig::Sp1 { elf_path } => {
            info!(proof = proof_name, elf_path = %elf_path.display(), "sp1 host: reading guest ELF");
            let read_started = Instant::now();
            let elf = std::fs::read(elf_path).with_context(|| {
                format!(
                    "failed to read {proof_name} guest ELF at {}",
                    elf_path.display()
                )
            })?;
            info!(
                proof = proof_name,
                elf_bytes = elf.len(),
                elapsed_ms = read_started.elapsed().as_millis() as u64,
                "sp1 host: ELF read complete; initializing SP1Host",
            );
            let init_started = Instant::now();
            let host = SP1Host::init(&elf).await;
            info!(
                proof = proof_name,
                elapsed_ms = init_started.elapsed().as_millis() as u64,
                "sp1 host: SP1Host::init complete",
            );
            Ok(Host::Sp1(Box::new(host)))
        }
        ProofBackendConfig::Native {
            schnorr_signing_key,
        } => {
            info!(proof = proof_name, "native host: initializing");
            Ok(Host::Native(NativeHost::new(
                schnorr_signing_key.clone(),
                native_processor,
            )))
        }
    }
}
