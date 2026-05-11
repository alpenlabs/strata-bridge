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

    /// The operator's BridgeProof tx, consensus-encoded.
    pub bridge_proof_tx: RawBitcoinTx,

    /// Prevouts of `bridge_proof_tx`, matching `tx.input` 1:1.
    pub bridge_proof_tx_prevouts: Vec<BitcoinTxOut>,
}

/// Public values committed by the counterproof.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct CounterproofOutput {
    /// Echoed `game_idx` from the input.
    pub game_idx: u32,

    /// Echoed operator master x-only pubkey.
    pub operator_pubkey: BitcoinXOnlyPublicKey,
}
