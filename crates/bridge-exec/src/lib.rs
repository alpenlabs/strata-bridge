//! This crate contains the various executors that perform duties emitted extrernally.
//!
//! The functions and modules defined here are designed to perform actions. An action is any
//! effectful operation that needs to be executed as part of the bridge's operation. This includes
//! tasks such as sending transactions, interacting with external services, etc.
//!
//! Each executor function has the following properties:
//! - It is an effectful function.
//! - It is an idempotent function i.e., its effects are deterministic and can be safely retried.
//! - It can be run asynchronously and independently of other executors.

mod chain;
pub mod config;
pub mod deposit;
pub mod errors;
pub mod graph;
pub mod output_handles;
