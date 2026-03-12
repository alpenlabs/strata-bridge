//! The state machine manages the lifecycle of an operator's stake.

pub mod config;
pub mod context;
pub mod duties;
pub mod errors;
pub mod events;
pub mod machine;
pub mod state;
mod transitions;

#[cfg(test)]
mod tests;
