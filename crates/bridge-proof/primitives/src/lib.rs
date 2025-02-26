//! This crate provides essential primitives for proving transaction inclusion in the Strata bridge.
//! It is a temporary separation from `strata-bridge-primitives` due to its dependency on `bitvm`,
//! which in turn depends on `tokio`, making it incompatible with compilation inside the ZKVM.
//!
//! **TODO:** Move this functionality back into `strata-bridge-primitives` once the dependency on
//! `tokio` inside `bitvm` is resolved.

#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in

mod tx;

mod tx_inclusion_proof;
pub use tx_inclusion_proof::*;
