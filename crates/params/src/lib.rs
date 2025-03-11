//! This crate contains the consensus-critical parameters that dictate the behavior of the brigde
//! node in a way that ensures that all nodes can come to a consensus on the state of the bridge.

pub mod connectors;
pub mod prelude;
pub mod sidesystem;
pub mod stake_chain;
pub mod tx;
pub mod tx_graph;
