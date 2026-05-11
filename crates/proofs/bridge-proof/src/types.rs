//! Wire types for the bridge proof program.

use moho_types::StateRefAttestation;
pub use moho_types::{MohoState, RecursiveMohoProof};
use ssz_derive::{Decode, Encode};
pub use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
pub use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;

/// Trust anchors used when verifying the recursive Moho proof.
#[derive(Debug, Encode, Decode)]
pub struct BridgeProofGenesis {
    /// Verifying key for the Moho proof.
    pub moho_vk: PredicateKey,

    /// Attested genesis state that the Moho transition is anchored against.
    pub genesis_moho_state: StateRefAttestation,
}

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
