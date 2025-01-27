use bitcoin::{FeeRate, Txid};
use strata_bridge_primitives::errors::BridgeTxBuilderError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxError {
    /// Error building the tx.
    #[error("build: {0}")]
    BuildTx(#[from] BridgeTxBuilderError),

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

pub type TxResult<T> = Result<T, TxError>;
