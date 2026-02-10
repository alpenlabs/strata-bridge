//! Errors related to the state transitions in the Graph State Machine.

use crate::{
    errors::BridgeSMError,
    graph::{events::GraphEvent, state::GraphState},
};

/// Errors that can occur in the Graph State Machine.
pub type GSMError = BridgeSMError<GraphState, GraphEvent>;

/// The result type for operations in the Graph State Machine.
pub type GSMResult<T> = Result<T, GSMError>;
