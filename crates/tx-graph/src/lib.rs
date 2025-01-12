//! This crate enables creating and verifying a transaction graph for a pegouts.

#![feature(duration_constructors)] // for constructing `Duration::from_days`
#![allow(incomplete_features)] // the feature below is used in size computations
#![feature(generic_const_exprs)]

pub mod connectors;
pub mod errors;
pub mod partial_verification_scripts;
pub mod peg_out_graph;
pub mod transactions;
