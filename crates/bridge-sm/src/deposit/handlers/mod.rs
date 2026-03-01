//! The handlers for the Deposit State Machine.
//!
//! Unlike transitions which mutate state, handlers only read the current state and emit duties
//! without causing state changes.

mod nag;
mod retry;
