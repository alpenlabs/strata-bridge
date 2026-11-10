//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
//!
//! Each driven transaction is a package with a pure state machine (`package`). The tracker owns
//! every package and is the only code that changes one, and the broadcaster sends parents bare.
//! All node access goes through `ChainAccess`.

mod broadcaster;
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
