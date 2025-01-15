//! This crate enables creating and verifying a transaction graph for a pegouts.

#![feature(duration_constructors)] // for constructing `Duration::from_days`
#![allow(incomplete_features)]
#![feature(generic_const_exprs)] // this feature is used in size computations
#![feature(array_try_from_fn)] // this feature is used to generate arrays in a fallible way

pub mod connectors;
pub mod errors;
pub mod partial_verification_scripts;
pub mod peg_out_graph;
pub mod transactions;
