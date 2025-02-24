//! Some connectors related to the stake chain can be spent in different ways, depending on the
//! witness data. This modules contains [`StakeSpendPath`] which represents the different ways that
//! a connector can be spent.

use bitcoin::taproot;
use secp256k1::schnorr;

/// Ways that a connector in the stake chain can be spent given various conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StakeSpendPath {
    /// The witness data is a single (aggregated) Schnorr [`Signature`](schnorr::Signature).
    Payout(schnorr::Signature),

    /// The witness data is a single (aggregated) Schnorr [`Signature`](taproot::Signature) in the
    /// Disprove transaction with SIGHASH_SINGLE.
    Disprove(taproot::Signature),

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
