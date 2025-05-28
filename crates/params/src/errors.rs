//! Errors for the bridge parameters.

use thiserror::Error;

/// Error while creating or validating a bridge tag.
#[derive(Debug, Clone, Error)]
pub enum TagError {
    /// Tag size is invalid - must be exactly 4 bytes.
    #[error("tag size must be exactly 4 bytes, got {0} bytes")]
    InvalidSize(usize),

    /// Failed to convert byte vector to fixed-size array.
    #[error("failed to convert Vec<u8> to [u8; 4]")]
    ConversionFailed,
}
