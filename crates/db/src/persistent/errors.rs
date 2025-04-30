use thiserror::Error;

/// Errors that can occur when interacting with the storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite: {0}")]
    Driver(#[from] sqlx::Error),

    #[error("conversion: {0}")]
    MismatchedTypes(String),

    #[error("data: {0}")]
    InvalidData(String),

    #[error("failed to serialize JSON data: {0}")]
    SerializeJson(#[from] serde_json::Error),
}
