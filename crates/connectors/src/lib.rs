//! This crate contains connectors for the transaction graph.
//!
//! Connectors represent UTXOs with specific locking/spending conditions.
//! Each connector is pure in that they encapsulate logic that needs to go into the locking script
//! in a bitcoin transaction and the corresponding logic that needs to go into the witness script.
//! This logic depends on data that is assumed to be provided to these connectors by a non-pure
//! caller through means such as querying a database or making a network call.
#![allow(incomplete_features)]
#![feature(generic_const_exprs)] // this feature is used in size computations
#![feature(array_try_from_fn)] // this feature is used to generate arrays in a fallible way

pub mod connector_a30;
pub mod connector_a31;
pub mod connector_c0;
pub mod connector_c1;
pub mod connector_cpfp;
pub mod connector_k;
pub mod connector_p;
pub mod connector_s;
pub mod connectors_a;
pub mod partial_verification_scripts;
pub mod witness_data;

pub mod prelude;
