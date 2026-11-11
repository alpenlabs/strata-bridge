//! The CPFP fee-bump implementation behind [`btc_tracker::cpfp::CpfpBumper`].

mod decide;
pub mod errors;
pub mod handle;
pub mod interfaces;
pub mod ladder;
#[cfg(test)]
mod ladder_tests;
pub mod observability;
mod sign;
pub mod submitpackage;
#[cfg(test)]
mod test_utils;
