//! The events that are relevant to the Graph State Machine.
//!
//! Depending upon the exact state that the state machine is in, these events will trigger
//! different transitions and emit duties that need to be performed and messages that need to be
//! propagated.

/// The external events that affect the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphEvent {}
