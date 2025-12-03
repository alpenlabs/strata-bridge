//! This crate enables the creation and verification of a Glock transaction graph.

#![feature(duration_constructors)] // for constructing `Duration::from_days`
#![allow(incomplete_features)]
#![feature(generic_const_exprs)] // this feature is used in size computations
#![feature(array_try_from_fn)] // this feature is used to generate arrays in a fallible way
#![feature(maybe_uninit_array_assume_init)] // this feature is used to implement deserialization for fixed length arrays bound to the assert
                                            // vector length

pub mod connectors;
pub mod transactions;
