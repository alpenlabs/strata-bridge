//! The state machine for managing the lifecycle of a deposit with respect to the multisig.
//!
//! This state machine handles the following:
//!
//! - The collection of nonces and partials for spending the deposit request.
//! - The tracking of the deposit request UTXO on chain.
//! - The tracking of the deposit UTXO on chain.
//! - The collection of nonces and partials for spending the deposit cooperatively.

pub mod config;
pub mod duties;
pub mod errors;
pub mod events;
pub mod state;

#[cfg(test)]
pub(super) mod testing;
