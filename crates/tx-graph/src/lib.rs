#![feature(duration_constructors)] // for constructing `Duration::from_days`
#![allow(incomplete_features)] // the feature below is used in size computations
#![feature(generic_const_exprs)]

use bitcoin::{hashes::Hash, Txid};

pub mod connectors;
pub mod db;
pub mod errors;
pub mod partial_verification_scripts;
pub mod peg_out_graph;
pub mod transactions;

pub fn mock_txid() -> Txid {
    // Create a mock Txid by hashing an arbitrary string or using a fixed byte array.
    // Here, we hash a fixed string to get a deterministic Txid for testing purposes.
    Txid::from_slice(&[0u8; 32]).expect("Failed to create Txid from bytes")
}
