//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time, bumping their fees through CPFP children when they
//! need it.
//!
//! Each driven transaction is a package with a pure state machine (`package`). The tracker owns
//! every package and is the only code that changes one. The broadcaster sends parents bare, and
//! the bumper runs the bumps and keeps the state of each child. All node access goes through
//! `ChainAccess`.

mod broadcaster;
mod bumper;
mod driver;
#[cfg(test)]
mod e2e_tests;
mod errors;
mod node;
mod package;
#[cfg(test)]
mod test_utils;
mod tracker;
#[cfg(test)]
mod tracker_tests;

pub use self::{
    driver::{TxDriver, TxDriverHealthHandle},
    errors::DriveErr,
};
