//! Some connectors related to the stake chain can be spent in different ways, depending on the
//! witness data. This modules contains [`StakeSpendPath`] which represents the different ways that
//! a connector can be spent.

use bitcoin::taproot;
use secp256k1::schnorr;

/// Ways that a connector in the stake chain can be spent given various conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StakeSpendPath {
    /// The witness data is a single (aggregated) Schnorr [`Signature`](taproot::Signature).
    PayoutOptimistic(schnorr::Signature),

    /// The witness data is a single (aggregated) Schnorr [`Signature`](schnorr::Signature).
    Payout(schnorr::Signature),

    /// The witness data is a single (aggregated) Schnorr [`Signature`](taproot::Signature) in the
    /// Disprove transaction with SIGHASH_SINGLE.
    Disprove(taproot::Signature),

    /// The witness data is a single (aggregated) Schnorr [`Signature`](taproot::Signature) in the
    /// Slash Stake transaction with SIGHASH_SINGLE.
    SlashStake(taproot::Signature),

    /// The witness data is a 32-byte hash preimage in BurnPayouts transaction.
    BurnPayouts([u8; 32]),

    /// The witness data are a single (aggregated) Schnorr [`Signature`](schnorr::Signature) and a
    /// 32-byte hash preimage when advancing the stake chain.
    Advance {
        /// The taproot [`Signature`](taproot::Signature).
        signature: taproot::Signature,

        /// The 32-byte hash preimage.
        preimage: [u8; 32],
    },
}

impl StakeSpendPath {
    /// Returns the index of the input in the PSBT that corresponds to the witness data.
    pub fn get_input_index(&self) -> u32 {
        match self {
            StakeSpendPath::PayoutOptimistic(_) => 4,
            StakeSpendPath::Payout(_) => 3,
            StakeSpendPath::Disprove(_) => 0,
            StakeSpendPath::SlashStake(_) => 0,
            StakeSpendPath::BurnPayouts(_) => 0,
            StakeSpendPath::Advance { .. } => 1,
        }
    }
}
