//! # `btc-notify`
//!
//! `btc-notify` is a crate to deliver real-time notifications on the latest transaction and block
//! events in the Bitcoin network.

#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)]
// but necessary for using const generic bounds in

// This cfg_attr is needed so that we can disable coverage in parts of the code that we don't want
// polluting coverage analysis. Removing this will cause this module to fail to compile.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod client;
mod config;
mod constants;
mod event;
mod state_machine;
pub mod subscription;
