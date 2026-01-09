//! Errors related to the state transitions in the Deposit State Machine.

use strata_bridge_primitives::types::OperatorIdx;
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

    /// A duplicate submission was received from an operator.
    #[error("Duplicate {item} received from operator {operator_idx}")]
    DuplicateSubmission {
        /// Description of what was duplicated (e.g., "payout nonce", "partial signature").
        item: String,
        /// The index of the operator who submitted a duplicate.
        operator_idx: OperatorIdx,
    },
}

/// The result type for operations in the Deposit State Machine.
pub type DSMResult<T> = Result<T, DSMError>;
