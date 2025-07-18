//! Errors for the transactions module.

use bitcoin::{psbt::ExtractTxError, Amount, FeeRate, Txid};
use strata_bridge_primitives::errors::BridgeTxBuilderError;
use thiserror::Error;

/// Transaction errors.
#[derive(Debug, Error)]
pub enum TxError {
    /// Error building the tx.
    #[error("build: {0}")]
    BuildTx(#[from] BridgeTxBuilderError),

    /// Failed to finalize a psbt.
    #[error("could not finalize psbt: {0}")]
    FinalizationFailed(#[from] Box<ExtractTxError>),

    /// Insufficient input amount.
    #[error("insufficient input amount, input: {0}, output: {0}")]
    InsufficientInputAmount(Amount, Amount),

    /// Provided output index is invalid for a transaction.
    #[error("invalid vout: {0}")]
    InvalidVout(u32),

    /// Provided transaction is unsigned.
    #[error("unsigned tx: {0}")]
    EmptyWitness(Txid),

    /// Witness format is invalid.
    #[error("could not parse: {0}")]
    Witness(String),

    /// Provided signatures are not enough.
    #[error("not enough signatures: expected: {0}, got: {1}")]
    NotEnoughSignatures(usize, usize),

    /// Supplied fee rate is invalid.
    #[error("invalid fee rate: {0}")]
    InvalidFeeRate(FeeRate),

    /// An unexpected error occurred.
    // HACK: This should only be used while developing, testing or bikeshedding the right variant
    // for a particular error.
    #[error("unexpected error occurred: {0}")]
    Unexpected(String),
}

/// A result type for transaction errors.
pub type TxResult<T> = Result<T, TxError>;
