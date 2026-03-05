//! Implementation of the [`BridgeDb`](crate::traits::BridgeDb) trait as a FoundationDB layer.

pub mod bridge_db;
pub mod cfg;
pub mod client;
pub mod dirs;
pub mod errors;
pub mod proof_db;
pub mod row_spec;
#[cfg(test)]
pub(crate) mod test_utils;

/// The FoundationDB layer identifier.
pub const LAYER_ID: &[u8] = b"strata-bridge-v1";
