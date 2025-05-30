//! Persistent database errors.

use thiserror::Error;

/// Errors that can occur when interacting with the database.
#[derive(Debug, Error)]
pub enum StorageError {
    /// An error occurred when interacting with the SQLite database.
    #[error("sqlite: {0}")]
    Driver(#[from] sqlx::Error),

    /// An error occurred when converting between types.
    #[error("conversion: {0}")]
    MismatchedTypes(String),

    /// An error occurred when validating data.
    #[error("data: {0}")]
    InvalidData(String),
}
