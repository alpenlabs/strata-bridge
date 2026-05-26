//! Wire types for the bridge counterproof program.

use ssz_derive::{Decode, Encode};
pub use strata_btc_types::{BitcoinTxOut, BitcoinXOnlyPublicKey, RawBitcoinTx};

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
}

/// Public values committed by the counterproof.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct CounterproofOutput {
    /// Echoed `game_idx` from the input.
    pub game_idx: u32,

    /// Echoed operator master x-only pubkey.
    pub operator_pubkey: BitcoinXOnlyPublicKey,
}
