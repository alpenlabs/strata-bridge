//! This crate contains general types, traits and pure functions that need to be shared across
//! multiple crates.
//!
//! It is not intended to be used directly by end users, but rather to be used as a dependency by
//! other crates. Also note that this crate lies at the bottom of the crate-hierarchy in this
//! workspace i.e., it does not depend on any other crate in this workspace.
#![feature(array_try_from_fn)]
#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in
// `scripts::transform::wots_to_byte_array`
#![feature(iter_array_chunks)]

pub mod bitcoin;
pub mod build_context;
pub mod deposit;
pub mod duties;
pub mod errors;
pub mod params;
pub mod scripts;
pub mod secp;
pub mod types;
pub mod withdrawal;
pub mod wots;

#[cfg(test)]
mod test_utils;
