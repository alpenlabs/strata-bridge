use thiserror::Error;

use crate::persistent::errors::StorageError;

/// Error type for the database.
#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    /// Error originating from the persistence layer.
    Storage(#[from] StorageError),
}

/// Wrapper type for database results.
pub type DbResult<T> = Result<T, DbError>;
