//! Types for the Strata P2P messaging protocol v2.
//!
//! This crate provides message types with compile-time type safety for MuSig2
//! nonce and signature exchange, replacing runtime discrimination via `SessionId`.

mod bitcoin;
mod descriptor;
mod graph_data;
mod messages;
mod operator;

pub use bitcoin::{PartialSignature, PubNonce};
pub use descriptor::PayoutDescriptor;
pub use graph_data::ClaimInput;
pub use messages::{GossipsubMsg, MuSig2Nonce, MuSig2Partial, UnsignedGossipsubMsg};
pub use operator::P2POperatorPubKey;
pub use strata_bridge_primitives::types::GraphIdx;
