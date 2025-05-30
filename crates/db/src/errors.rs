//! Database errors.

use thiserror::Error;

use crate::persistent::errors::StorageError;

/// Error type for the database.
#[derive(Debug, Error)]
pub enum DbError {
    /// Error originating from the persistence layer.
    #[error("sqlite: {0}")]
    Storage(#[from] StorageError),

    /// Unexpected catch-all errors.
    #[error("unexpected: {0}")]
    Unexpected(String),
}

/// Wrapper type for database results.
pub type DbResult<T> = Result<T, DbError>;
