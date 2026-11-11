//! Errors of a CPFP bump and of the seams it calls.

use thiserror::Error;

/// A mempool query could not complete.
#[derive(Debug, Clone, Error)]
#[error("mempool: {0}")]
pub struct MempoolError(pub String);

/// An input signer could not produce a signature.
///
/// The bump skips and the next trigger retries. A signer fault does not stop the bumps for a
/// parent, whichever signer it comes from.
#[derive(Debug, Clone, Error)]
#[error("{0}")]
pub struct SignerError(pub String);

/// Why a wallet could not build a CPFP child.
///
/// The cases lead to different driver behaviour, so the boundary reports which one it is rather
/// than one message that the driver has to read.
#[derive(Debug, Error)]
pub enum CpfpWalletError {
    /// The parent cannot carry a child, whatever the wallet does. Its anchor is not where the
    /// strategy says, or the wallet cannot spend it. A signed parent does not change shape, so
    /// every later attempt fails at the same step.
    #[error("parent cannot carry a child: {0}")]
    Unbumpable(String),
    /// The wallet could not fund a child now. Funds arrive, the chain moves, and a later
    /// attempt can pass.
    #[error("{0}")]
    Transient(String),
}
