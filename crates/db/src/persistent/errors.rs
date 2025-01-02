use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite: {0}")]
    Driver(#[from] sqlx::Error),

    #[error("conversion: {0}")]
    MismatchedTypes(String),

    #[error("data: {0}")]
    InvalidData(String),
}
