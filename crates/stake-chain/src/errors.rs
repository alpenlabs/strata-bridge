//! Errors that can occur in the stake chain and the underlying transactions.

use bitcoin::psbt::{Error as PsbtError, ExtractTxError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StakeChainError {
    /// Cannot extract a transaction from a [`Psbt`](bitcoin::Psbt).
    #[error("cannot extract a transaction from a PSBT: {0}")]
    CannotExtractTx(#[from] ExtractTxError),

    /// Ways that a [`Psbt`](bitcoin::Psbt) might fail.
    #[error("PSBT error: {0}")]
    Psbt(#[from] PsbtError),
}
