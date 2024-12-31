use thiserror::Error;

use crate::{inmemory, persistent::errors::StorageError};

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Storage(#[from] StorageError),

    #[error("memory: {0}")]
    InMemory(#[from] inmemory::prelude::Error),
}

pub type DbResult<T> = Result<T, DbError>;
