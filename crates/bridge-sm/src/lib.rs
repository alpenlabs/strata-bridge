//! This crate implements state machines for managing bridge operations.
//!
//! The state machines in the bridge are a cooperating automata that together implement the overall
//! logic of the bridge. These state machines can push each other around by sending signals to each
//! other, and each state machine can also emit duties that need to be executed externally to
//! effect the desired operations.

pub mod deposit;
pub mod signals;
