//! Contains execution logic for various duties emitted by the contract manager event loop.

pub mod config;
pub(crate) mod constants;
pub(crate) mod contested_withdrawal;
pub(crate) mod deposit;
pub(crate) mod optimistic_withdrawal;
pub(crate) mod prelude;
pub(crate) mod proof_handler;
pub(crate) mod wots_handler;
