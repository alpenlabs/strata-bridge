//! This crate contains general types, traits and pure functions that need to be shared across
//! multiple crates.
//!
//! It is not intended to be used directly by end users, but rather to be used as a dependency by
//! other crates. Also note that this crate lies at the bottom of the crate-hierarchy in this
//! workspace i.e., it does not depend on any other crate in this workspace.

pub mod bitcoin;
pub mod build_context;
pub mod constants;
pub mod errors;
pub mod key_agg;
pub mod mosaic;
pub mod operator_table;
pub mod proof;
pub mod scripts;
pub mod secp;
#[cfg(feature = "async")]
pub mod subscription;
pub mod types;
