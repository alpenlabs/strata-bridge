//! Implementation of the [`BridgeDb`](crate::traits::BridgeDb) trait as a FoundationDB layer.

pub mod bridge_db;
pub mod cfg;
pub mod client;
pub mod dirs;
pub mod row_spec;

/// The FoundationDB layer identifier.
pub const LAYER_ID: &[u8] = b"strata-bridge-v1";
