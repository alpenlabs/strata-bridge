use strata_bridge_primitives::errors::BridgeTxBuilderError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TxError {
    /// Error building the tx.
    #[error("build: {0}")]
    BuildTx(#[from] BridgeTxBuilderError),

    /// An unexpected error occurred.
    // HACK: This should only be used while developing, testing or bikeshedding the right variant
    // for a particular error.
    #[error("unexpected error occurred: {0}")]
    Unexpected(String),
}

pub type TxResult<T> = Result<T, TxError>;
