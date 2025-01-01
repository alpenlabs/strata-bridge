//! This crate contains general types, traits and pure functions that need to be shared across
//! multiple crates.
//!
//! It is not intended to be used directly by end users, but rather to be used as a dependency by
//! other crates. Also note that this crate lies at the bottom of the crate-hierarchy in this
//! workspace i.e., it does not depend on any other crate in this workspace.
pub mod bitcoin;
pub mod build_context;
pub mod deposit;
pub mod duties;
pub mod params;
pub mod scripts;
pub mod types;
pub mod withdrawal;
pub mod wots;
