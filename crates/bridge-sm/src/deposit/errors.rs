//! Errors related to the state transitions in the Deposit State Machine.

use thiserror::Error;

use crate::deposit::{events::DepositEvent, state::DepositState};

/// Errors that can occur in the Deposit State Machine.
#[derive(Debug, Clone, Error)]
pub enum DSMError {
    /// An invalid event was received for the current state.
    ///
    /// This type of error is usually fatal.
    #[error("Received invalid event {event} in state {state}; reason: {reason:?}")]
    InvalidEvent {
        /// The state in which the event was received.
        state: String,
        /// The invalid event that was received.
        event: String,
        /// The reason for the invalidity.
        reason: Option<String>, // sometimes the reason is obvious from context or unknown
    },

    /// A duplicate event was received in the current state.
    #[error("Received a duplicate event {event} in state {state}")]
    Duplicate {
        /// The state in which the duplicate event was received.
        state: Box<DepositState>,
        /// The duplicate event that was received.
        event: Box<DepositEvent>,
    },

    /// An event was rejected in the current state.
    ///
    /// This can happen, for example, if the event is no longer relevant due to a state change.
    #[error("Event {event} rejected in state: {state}, reason: {reason}")]
    Rejected {
        /// The state in which the event was rejected.
        // NOTE: (@Rajil1213) Since errors are supposed to be rare, owning the DepositState here is
        // acceptable.
        state: Box<DepositState>,
        /// The reason for the rejection.
        reason: String, // rejection reason is a must
        /// The rejected event.
        event: Box<DepositEvent>,
    },
}

/// The result type for operations in the Deposit State Machine.
pub type DSMResult<T> = Result<T, DSMError>;
