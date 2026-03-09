//! Error types for the Stake State Machine.

use crate::{
    errors::BridgeSMError,
    stake::{events::StakeEvent, state::StakeState},
};

/// An error when the Stake State Machine fails to process an event.
pub type SSMError = BridgeSMError<StakeState, StakeEvent>;

/// Wrapper for [`Result<T, SSMError>`].
pub type SSMResult<T> = Result<T, SSMError>;
