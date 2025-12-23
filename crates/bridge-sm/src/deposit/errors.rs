//! Errors related to the state transitions in the Deposit State Machine.

use thiserror::Error;

/// Errors that can occur in the Deposit State Machine.
#[derive(Debug, Clone, Error)]
pub enum DSMError {
    /// An invalid event was received for the current state.
    #[error("Received invalid event {event} in state {state}")]
    InvalidEvent {
        /// The state in which the event was received.
        state: String,
        /// The invalid event that was received.
        event: String,
    },
}

/// The result type for operations in the Deposit State Machine.
pub type DSMResult<T> = Result<T, DSMError>;
