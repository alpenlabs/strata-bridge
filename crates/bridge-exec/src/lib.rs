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

#![allow(
    incomplete_features,
    reason = "required for the feature below in order to compile strata-p2p"
)]
#![feature(generic_const_exprs)] // FIXME: (@Rajil1213) remove this once strata-p2p is updated

pub mod config;
pub mod deposit;
pub mod output_handles;
