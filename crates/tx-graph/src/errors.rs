//! Error types for the transaction graph.

use bitcoin::Txid;
use strata_bridge_db::errors::DbError;
use strata_bridge_primitives::types::OperatorIdx;
use thiserror::Error;

use crate::transactions::errors::TxError;

/// Errors that can occur while working with the transaction graph.
#[derive(Debug, Error)]
pub enum TxGraphError {
    /// Error while constructing a transaction.
    #[error("Transaction: {0}")]
    TxError(#[from] TxError),

    /// Error while interacting with the database.
    #[error("Database: {0}")]
    DbError(#[from] DbError),

    /// Missing WOTS public keys for a given operator and deposit transaction.
    #[error("Missing WOTS public keys for operator {0} and deposit transaction {1}")]
    MissingWotsPublicKeys(OperatorIdx, Txid),
}

/// Wrapper type for results that can fail with a `TxGraphError`.
pub type TxGraphResult<T> = Result<T, TxGraphError>;
