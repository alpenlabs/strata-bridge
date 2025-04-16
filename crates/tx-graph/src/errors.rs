//! Error types for the transaction graph.

use bitcoin::Txid;
use strata_bridge_primitives::types::OperatorIdx;
use thiserror::Error;

use crate::transactions::errors::TxError;

/// Errors that can occur while working with the transaction graph.
#[derive(Debug, Error)]
pub enum TxGraphError {
    /// Error while constructing a transaction.
    #[error("Transaction: {0}")]
    TxError(#[from] TxError),

    /// Missing N-of-N signature for a given operator, transaction and input index.
    #[error("Missing N-of-N signature for operator {0}, transaction {1} and input index {2}")]
    MissingNOfNSignature(OperatorIdx, Txid, u32),

    /// Missing WOTS public keys for a given operator and deposit transaction.
    #[error("Missing WOTS public keys for operator {0} and deposit transaction {1}")]
    MissingWotsPublicKeys(OperatorIdx, Txid),
}

/// Wrapper type for results that can fail with a `TxGraphError`.
pub type TxGraphResult<T> = Result<T, TxGraphError>;
