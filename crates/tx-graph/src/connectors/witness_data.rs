//! Some connectors can be spent in different ways, depending on the witness data.
//! This modules contains [`WitnessData`] which represents the different ways that a connector can
//! be spent given the witness data.

use secp256k1::schnorr;

/// Ways that a connector can be spent given the witness data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive] // We might want to add more variants in the future.
pub enum WitnessData {
    /// The witness data is a single (aggregated) Schnorr [`Signature`](schnorr::Signature).
    Signature(schnorr::Signature),

    /// The witness data is a 32-byte hash preimage.
    Preimage([u8; 32]),

    /// The witness data are a single (aggregated) Schnorr [`Signature`](schnorr::Signature) and a
    /// 32-byte hash preimage.
    SignaturePreimage {
        /// The Schnorr [`Signature`](schnorr::Signature).
        signature: schnorr::Signature,

        /// The 32-byte hash preimage.
        preimage: [u8; 32],
    },
}
