//! The state machine manages the lifecycle of an operator's stake.

pub mod config;
pub mod context;
pub mod duties;
pub mod errors;
pub mod events;
mod handlers;
pub mod machine;
pub mod state;
mod transitions;
mod tx_classifier;

#[cfg(test)]
mod tests;
