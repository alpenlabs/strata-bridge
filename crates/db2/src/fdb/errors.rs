//! Errors related to FoundationDB layers.
use std::fmt::Debug;

/// Distinction between key and value failures.
#[derive(Debug)]
pub enum FailureTarget {
    /// Key-related failure.
    Key,
    /// Value-related failure.
    Value,
}

/// Standard error type for FoundationDB layer errors
#[derive(Debug)]
pub enum LayerError {
    /// Something failed to decode. This cannot be programmatically
    /// introspected and should be logged.
    FailedToDeserialize(FailureTarget, Box<dyn Debug + Send + Sync>),

    /// Something failed to encode. This cannot be programmatically
    /// introspected and should be logged.
    FailedToSerialize(FailureTarget, Box<dyn Debug + Send + Sync>),
}

impl LayerError {
    /// Creates a new `LayerError` for a failed key unpacking.
    pub fn failed_to_unpack_key(error: impl Debug + Send + Sync + 'static) -> Self {
        LayerError::FailedToDeserialize(FailureTarget::Key, Box::new(error))
    }

    /// Creates a new `LayerError` for a failed key serialization.
    pub fn failed_to_pack_key(error: impl Debug + Send + Sync + 'static) -> Self {
        LayerError::FailedToSerialize(FailureTarget::Key, Box::new(error))
    }

    /// Creates a new `LayerError` for a failed value deserialization.
    pub fn failed_to_deserialize_value(error: impl Debug + Send + Sync + 'static) -> Self {
        LayerError::FailedToDeserialize(FailureTarget::Value, Box::new(error))
    }

    /// Creates a new `LayerError` for a failed value serialization.
    pub fn failed_to_serialize_value(error: impl Debug + Send + Sync + 'static) -> Self {
        LayerError::FailedToSerialize(FailureTarget::Value, Box::new(error))
    }
}
