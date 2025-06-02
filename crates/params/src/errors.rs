//! Errors for the bridge parameters.

use thiserror::Error;

use crate::types::TAG_SIZE;

/// Error while creating or validating a bridge tag.
#[derive(Debug, Clone, Error)]
pub enum TagError {
    /// Tag size is invalid - must be exactly [`TAG_SIZE`] bytes.
    #[error("tag size must be exactly {TAG_SIZE} bytes, got {0} bytes")]
    InvalidSize(usize),

    /// Failed to convert byte vector to fixed-size array.
    #[error("failed to convert Vec<u8> to [u8; {TAG_SIZE}]")]
    ConversionFailed,
}
