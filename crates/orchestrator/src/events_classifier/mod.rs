//! Classification of external events into state-machine-specific events.
//!
//! - [`offchain`]: P2P gossip, requests, and assignment classification
//! - [`onchain`]: Block scanning, TxClassifier, and NewBlock cursor events

pub mod offchain;
pub mod onchain;
