//! Wire types for the bridge counterproof program.

pub use moho_types::{MohoState, RecursiveMohoProof};
use ssz_derive::{Decode, Encode};
pub use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
pub use strata_btc_types::{BitcoinTxOut, BitcoinXOnlyPublicKey, RawBitcoinTx};
pub use strata_merkle::MerkleProofB32;

/// Proof of a heavier chain.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct HeavierChainProof {
    /// Moho state.
    pub moho_state: MohoState,

    /// Validity proof of `moho_state`.
    pub moho_proof: RecursiveMohoProof,

    /// [`OperatorClaimUnlock`] encoded via `strata_codec::Codec`.
    pub claim_unlock: Vec<u8>,

    /// Inclusion proof for `claim_unlock` in `moho_state`.
    pub claim_unlock_inclusion_proof: MerkleProofB32,
}

/// Possible ways to generate a counterproof.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum CounterproofMode {
    /// The counterproof is valid if the bridge proof is valid.
    InvalidBridgeProof,
    /// The counterproof is valid if there is a heavier chain,
    /// compared to the operator chain used in the bridge proof.
    HeavierChain(HeavierChainProof),
}

/// Inputs to the counterproof program.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct CounterproofInput {
    /// Public input: game index used to derive the per-game operator tweak.
    pub game_idx: u32,

    /// Public input: operator master x-only pubkey (BIP-340).
    pub operator_pubkey: BitcoinXOnlyPublicKey,

    /// N-of-N covenant x-only pubkey pushed into the `ContestProofConnector`
    pub n_of_n_pubkey: BitcoinXOnlyPublicKey,

    /// Relative-height timelock (in blocks) encoded into the
    /// `ContestProofConnector` tap-leaf
    pub proof_timelock: u16,

    /// The operator's BridgeProof tx, consensus-encoded.
    pub bridge_proof_tx: RawBitcoinTx,

    /// Prevouts of `bridge_proof_tx`, matching `tx.input` 1:1.
    pub bridge_proof_tx_prevouts: Vec<BitcoinTxOut>,

    /// Index of `bridge_proof_tx` input that spends the `ContestProofConnector`.
    pub bridge_proof_tx_input_idx: u32,

    /// Mode for the counterproof.
    pub mode: CounterproofMode,
}

/// Public values committed by the counterproof.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct CounterproofOutput {
    /// Echoed `game_idx` from the input.
    pub game_idx: u32,

    /// Echoed operator master x-only pubkey.
    pub operator_pubkey: BitcoinXOnlyPublicKey,
}
