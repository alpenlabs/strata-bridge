//! Errors related to the state transitions in the State Machine.

use thiserror::Error;

/// Errors that can occur in the  State Machine.
#[derive(Debug, Clone, Error)]
pub enum BridgeSMError<S, E>
where
    S: std::fmt::Display + std::fmt::Debug,
    E: std::fmt::Display + std::fmt::Debug,
{
    /// An invalid event was received for the current state.
    ///
    /// This type of error is usually fatal.
    #[error("Received invalid event {event} in state {state}; reason: {reason:?}")]
    InvalidEvent {
        /// The state in which the event was received.
        state: Box<S>,
        /// The invalid event that was received.
        event: Box<E>,
        /// The reason for the invalidity.
        reason: Option<String>, // sometimes the reason is obvious from context or unknown
    },

    /// A duplicate event was received in the current state.
    #[error("Received a duplicate event {event} in state {state}")]
    Duplicate {
        /// The state in which the duplicate event was received.
        state: Box<S>,
        /// The duplicate event that was received.
        event: Box<E>,
    },

    /// An event was rejected in the current state.
    ///
    /// This can happen, for example, if the event is no longer relevant due to a state change.
    #[error("Event {event} rejected in state: {state}, reason: {reason}")]
    Rejected {
        /// The state in which the event was rejected.
        state: Box<S>,
        /// The reason for the rejection.
        reason: String, // rejection reason is a must
        /// The rejected event.
        event: Box<E>,
    },
}

impl<S, E> BridgeSMError<S, E>
where
    S: std::fmt::Display + std::fmt::Debug,
    E: std::fmt::Display + std::fmt::Debug,
{
    pub(super) fn invalid_event(state: S, event: E, reason: Option<String>) -> Self {
        BridgeSMError::InvalidEvent {
            state: Box::new(state),
            event: Box::new(event),
            reason,
        }
    }

    pub(super) fn duplicate(state: S, event: E) -> Self {
        BridgeSMError::Duplicate {
            state: Box::new(state),
            event: Box::new(event),
        }
    }

    pub(super) fn rejected(state: S, event: E, reason: impl Into<String>) -> Self {
        BridgeSMError::Rejected {
            state: Box::new(state),
            reason: reason.into(),
            event: Box::new(event),
        }
    }
}
