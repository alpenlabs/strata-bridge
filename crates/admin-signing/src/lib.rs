//! Validated, claim-specific admin signatures that permit later transaction funding.
//!
//! This crate builds the fixed admin-burn signing template and delegates signing to an
//! [`AdminSigner`]. It does not select funding, access a wallet, or broadcast transactions.
//! The caller supplies the claim transaction and is responsible for checking its chain status.

mod request;
mod signer;

pub use request::{AdminSigningParams, AdminSigningRequest, RequestError, ADMIN_SIGHASH_TYPE};
pub use signer::{AdminSigner, SigningError};

#[cfg(test)]
mod tests;
