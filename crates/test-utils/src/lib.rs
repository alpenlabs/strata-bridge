//! This crate provides test-utilities related to external libraries.
//!
//! These utilities are mostly used to generate arbitrary values for testing purposes, where
//! implementing `Arbitrary` is not feasible due to the orphan rule (without using newtypes for
//! everything).

pub mod arbitrary_generator;
pub mod bitcoin;
pub mod bitcoin_rpc;
pub mod musig2;
pub mod prelude;
pub mod tx;
pub mod wots;
