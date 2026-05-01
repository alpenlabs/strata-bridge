//! Shared proving primitives reused by every per-program proof crate
//! (e.g. `strata-bridge-proof`).

use thiserror::Error;
use tokio::task::JoinError;
use zkaleido::{ProofReceipt, ZkVmError, ZkVmExecutor, ZkVmHost, ZkVmInputBuilder, ZkVmProgram};

/// Errors returned by [`prove`].
#[derive(Debug, Error)]
pub enum ProofError {
    /// Proving inside the zkVM (or its native adapter) failed.
    #[error("zkvm proving failed: {0}")]
    ZkVm(#[from] ZkVmError),

    /// The blocking proving task panicked or was cancelled.
    #[error("proving task join error: {0}")]
    Join(#[from] JoinError),
}

/// Generates a proof for `P` using `host`.
///
/// Runs on a `spawn_blocking` worker so CPU-bound native execution doesn't
/// stall the async runtime. The host is consumed (cloned at the call site
/// when shared); both `NativeHost` and `SP1Host` are cheap to clone.
pub async fn prove<P, H>(input: P::Input, host: H) -> Result<ProofReceipt, ProofError>
where
    P: ZkVmProgram + 'static,
    P::Input: Send + 'static,
    P::Output: 'static,
    H: ZkVmHost + Clone + Send + Sync + 'static,
    for<'a> <H as ZkVmExecutor>::Input<'a>: ZkVmInputBuilder<'a>,
{
    let receipt_with_meta = tokio::task::spawn_blocking(move || P::prove(&input, &host)).await??;
    Ok(receipt_with_meta.receipt().clone())
}
