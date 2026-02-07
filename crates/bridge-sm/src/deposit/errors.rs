//! Errors related to the state transitions in the Deposit State Machine.
use crate::{
    deposit::{events::DepositEvent, state::DepositState},
    errors::BridgeSMError,
};

/// Errors that can occur in the Deposit State Machine.
pub type DSMError = BridgeSMError<DepositState, DepositEvent>;

/// The result type for operations in the Deposit State Machine.
pub type DSMResult<T> = Result<T, DSMError>;
