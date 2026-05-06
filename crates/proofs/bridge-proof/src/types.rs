//! Wire types for the bridge proof program.

pub use moho_types::{MohoState, RecursiveMohoProof};
use ssz_derive::{Decode, Encode};
pub use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
pub use strata_merkle::MerkleProofB32;

/// Inputs to the bridge proof program.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BridgeProofInput {
    /// Moho state that the Moho proof attests to.
    pub moho_state: MohoState,

    /// Recursive Moho proof.
    pub moho_proof: RecursiveMohoProof,

    /// `strata_codec::Codec` encoded [`OperatorClaimUnlock`].
    pub claim_unlock: Vec<u8>,

    /// MMR inclusion proof for `claim_unlock` in `moho_state`.
    pub claim_unlock_inclusion_proof: MerkleProofB32,
}

/// Public values committed by the bridge proof.
#[derive(Debug, Clone, Default, PartialEq, Eq, Encode, Decode)]
pub struct BridgeProofOutput {
    /// Accumulated PoW from the bridge-v1 export container in the Moho state.
    pub total_pow: [u8; 32],

    /// Same wire as [`BridgeProofInput::claim_unlock`].
    pub claim_unlock: Vec<u8>,

    /// MMR index at which `claim_unlock` was included.
    pub mmr_idx: u64,
}
