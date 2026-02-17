//! Errors related to FoundationDB layers.
use std::fmt::Debug;

use foundationdb::{FdbBindingError, FdbError, TransactError};
use terrors::OneOf;

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

/// Internal error type for `transact_boxed` closures.
///
/// `Fdb` errors are retryable (conflict, timeout, etc.).
/// `Layer` errors are deterministic and abort the retry loop immediately.
pub(super) enum TransactionError {
    Fdb(FdbError),
    Layer(LayerError),
}

impl From<FdbError> for TransactionError {
    fn from(e: FdbError) -> Self {
        TransactionError::Fdb(e)
    }
}

impl TransactError for TransactionError {
    fn try_into_fdb_error(self) -> Result<FdbError, Self> {
        match self {
            TransactionError::Fdb(e) => Ok(e),
            other => Err(other),
        }
    }
}

impl From<TransactionError> for OneOf<(FdbBindingError, LayerError)> {
    fn from(e: TransactionError) -> Self {
        match e {
            TransactionError::Fdb(e) => OneOf::new(FdbBindingError::from(e)),
            TransactionError::Layer(e) => OneOf::new(e),
        }
    }
}
