//! Types for the Strata P2P messaging protocol v2.
//!
//! This crate provides message types with compile-time type safety for MuSig2
//! nonce and signature exchange, replacing runtime discrimination via `SessionId`.

// serde_json is only used in proptest tests
#[cfg(feature = "proptest")]
use serde_json as _;
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

mod bitcoin;
mod descriptor;
mod messages;
mod operator;

pub use bitcoin::{PartialSignature, PubNonce};
pub use descriptor::PayoutDescriptor;
pub use messages::{GossipsubMsg, MuSig2Nonce, MuSig2Partial, UnsignedGossipsubMsg};
pub use operator::P2POperatorPubKey;

/// Graph index identifying a specific transaction graph.
///
/// Tuple of (operator_idx, deposit_idx).
pub type GraphIdx = (OperatorIdx, DepositIdx);
