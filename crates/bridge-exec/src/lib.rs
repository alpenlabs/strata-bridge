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
pub mod stake;

// Dev-deps only used by the `tests/` integration tests; silence the lib-test build's
// unused-crate-dependencies warning.
#[cfg(test)]
use ark_ec as _;
#[cfg(test)]
use ark_ff as _;
#[cfg(test)]
use ark_secp256k1 as _;
#[cfg(test)]
use mosaic_adaptor_sigs as _;
#[cfg(test)]
use rand as _;
#[cfg(test)]
use sp1_verifier as _;
#[cfg(test)]
use zkaleido_sp1_groth16_verifier as _;
