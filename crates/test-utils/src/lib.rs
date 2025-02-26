//! This crate provides test-utilities related to external libraries.
//!
//! These utilities are mostly used to generate arbitrary values for testing purposes, where
//! implementing `Arbitrary` is not feasible due to the orphan rule (without using newtypes for
//! everything).

#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in

pub mod arbitrary_generator;
pub mod bitcoin;
pub mod musig2;
pub mod prelude;
pub mod tx;
pub mod wots;
