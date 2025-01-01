use thiserror::Error;

use crate::{inmemory, persistent::errors::StorageError};

/// Error type for the database.
#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    /// Error originating from the persistence layer.
    Storage(#[from] StorageError),

    #[error("memory: {0}")]
    /// Error originating from the in-memory impl.
    InMemory(#[from] inmemory::prelude::Error),
}

/// Wrapper type for database results.
pub type DbResult<T> = Result<T, DbError>;
