//! Wire types for the bridge counterproof program.

pub use moho_types::{MohoState, RecursiveMohoProof, StateRefAttestation};
use ssz_derive::{Decode, Encode};
pub use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
pub use strata_btc_types::{BitcoinTxOut, BitcoinXOnlyPublicKey, RawBitcoinTx};
use strata_codec::encode_to_vec;
pub use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;

/// Trust anchors for verifying bridge proofs and Moho proofs.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BridgeCounterproofGenesis {
    /// Verifying key for the bridge proof.
    pub bridge_proof_vk: PredicateKey,

    /// Verifying key for the Moho proof.
    pub moho_vk: PredicateKey,

    /// Attestation to the Moho genesis state.
    pub genesis_moho_state: StateRefAttestation,
}

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

impl HeavierChainProof {
    /// Creates a new heavier chain proof.
    pub fn new(
        moho_state: MohoState,
        moho_proof: RecursiveMohoProof,
        claim_unlock: OperatorClaimUnlock,
        inclusion_proof: MerkleProofB32,
    ) -> Self {
        Self {
            moho_state,
            moho_proof,
            claim_unlock: encode_to_vec::<OperatorClaimUnlock>(&claim_unlock)
                .expect("encode to vector should never fail"),
            claim_unlock_inclusion_proof: inclusion_proof,
        }
    }
}

/// Possible ways to generate a counterproof.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
#[expect(
    clippy::large_enum_variant,
    reason = "300 extra bytes that are immediately destructured in the counterproof statement are a low cost for the zkVM"
)]
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
