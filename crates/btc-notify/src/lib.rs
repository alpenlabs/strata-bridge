//! # `btc-notify`
//!
//! `btc-notify` is a crate to deliver real-time notifications on the latest transaction and block
//! events in the Bitcoin network.

pub mod client;
mod config;
mod constants;
mod event;
mod state_machine;
pub mod subscription;
