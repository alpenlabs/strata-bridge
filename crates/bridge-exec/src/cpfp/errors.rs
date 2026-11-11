//! Errors of a CPFP bump and of the seams it calls.

use bitcoin::Txid;
use thiserror::Error;

use super::submitpackage::{ReplacementRejection, SubmitPackageError};
use crate::fees::FeeSourceError;

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

/// Errors produced by [`perform_bump`](super::ladder::perform_bump).
#[derive(Debug, Error)]
pub enum CpfpError {
    /// The fee source lookup failed. The bump is skipped; the next trigger will retry.
    #[error("{0}")]
    FeeSource(#[from] FeeSourceError),
    /// The wallet could not build the child.
    #[error("wallet: {0}")]
    Wallet(#[from] CpfpWalletError),
    /// The anchor input signer returned an error. The bump is skipped; the next trigger
    /// will retry.
    #[error("anchor signer: {0}")]
    AnchorSigner(SignerError),
    /// A signer of the wallet inputs returned an error. The bump is skipped; the next trigger
    /// will retry.
    #[error("wallet input signer: {0}")]
    WalletSigner(SignerError),
    /// `submitpackage` returned a non-success outcome. Logged + bump skipped.
    #[error("submit_package: {0}")]
    SubmitPackage(#[from] SubmitPackageError),
    /// The wallet returned a child that has no fee, no anchor, or no valid sighash, or a child
    /// that does not extract after signing.
    #[error("malformed child: {0}")]
    MalformedChild(String),
}

impl CpfpError {
    /// Which replacement rule the node applied to reject a package member.
    pub fn replacement_rejection(&self) -> Option<ReplacementRejection> {
        match self {
            Self::SubmitPackage(e) => e.replacement_rejection(),
            _ => None,
        }
    }

    /// Whether the transaction `txid` itself lost a replacement race. See
    /// [`SubmitPackageError::is_replacement_contention_for`].
    pub fn is_replacement_contention_for(&self, txid: &Txid) -> bool {
        matches!(self, Self::SubmitPackage(e) if e.is_replacement_contention_for(txid))
    }
}
