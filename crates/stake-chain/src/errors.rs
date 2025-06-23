//! Errors that can occur in the stake chain and the underlying transactions.

use bitcoin::psbt::{Error as PsbtError, ExtractTxError};
use thiserror::Error;

/// Errors that can occur in the stake chain and the underlying transactions.
#[derive(Debug, Error)]
pub enum StakeChainError {
    /// Cannot extract a signed transaction from a [`Psbt`](bitcoin::Psbt).
    #[error("cannot extract a signed transaction from a PSBT: {0}")]
    CannotExtractTx(#[from] Box<ExtractTxError>),

    /// Ways that a [`Psbt`](bitcoin::Psbt) might fail.
    #[error("PSBT error: {0}")]
    Psbt(#[from] PsbtError),

    /// Signature failure.
    #[error("signature failure")]
    SignatureFailure,
}
