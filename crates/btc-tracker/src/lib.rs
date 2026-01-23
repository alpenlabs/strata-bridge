//! # `btc-tracker`
//!
//! `btc-tracker` is a crate to deliver real-time notifications on the latest transaction and block
//! events in the Bitcoin network.
#![feature(coverage_attribute)]

pub mod client;
pub mod config;
mod constants;
pub mod event;
mod state_machine;
pub mod tx_driver;

// Re-exports
pub use state_machine::TxPredicate;
