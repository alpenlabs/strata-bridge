//! This crate provides test-utilities related to external libraries.
//!
//! These utilities are mostly used to generate arbitrary values for testing purposes, where
//! implementing `Arbitrary` is not feasible due to the orphan rule (without using newtypes for
//! everything).

#![expect(incomplete_features)]
#![feature(generic_const_exprs)]
// This cfg_attr is needed so that we can disable coverage in parts of the code that we don't want
// polluting coverage analysis. Removing this will cause this module to fail to compile.
#![feature(coverage_attribute)]
pub mod arbitrary_generator;
pub mod bitcoin;
pub mod bitcoin_rpc;
pub mod bridge_fixtures;
pub mod deposit;
pub mod musig2;
pub mod prelude;
pub mod tx;
pub mod wots;
