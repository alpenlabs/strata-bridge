//! Common types for mosaic client

use bitcoin::XOnlyPublicKey;
pub use bitcoin::secp256k1::schnorr::Signature;
pub use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

/// Number of setup input wire groups.
pub const N_SETUP_INPUT_WIRES: usize = 32;
/// Number of deposit input wire groups.
pub const N_DEPOSIT_INPUT_WIRES: usize = 4;
/// Number of withdrawal input wire groups.
pub const N_WITHDRAWAL_INPUT_WIRES: usize = 128;

/// A Txn sighash to be signed.
pub type Sighash = [u8; 32];
/// A Public key for Schnorr signatures.
pub type PubKey = XOnlyPublicKey;

/// Mosaic Role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Garbler
    Garbler,
    /// Evaluator
    Evaluator,
}

/// Inputs for setup input wires. Corresponds to operator pubkey.
pub type SetupInputs = [u8; N_SETUP_INPUT_WIRES];
/// Inputs for deposit input wires. Corresponds to deposit idx.
pub type DepositInputs = [u8; N_DEPOSIT_INPUT_WIRES];
/// Inputs for withdrawal input wires. Corresponds to counterproof.
pub type WithdrawalInputs = [u8; N_WITHDRAWAL_INPUT_WIRES];

/// Txn sighashes to be used in adaptor signatures.
pub type DepositSighashes = [Sighash; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES];
/// Completed adaptor signatures corresponding to the [`DeposiSighashes`].
pub type CompletedSignatures = [Signature; N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES];

/// Raw Groth16 proof bytes.
#[derive(Debug, Clone, Copy)]
pub struct G16ProofRaw(pub [u8; 128]);

#[cfg(test)]
mod tests {
    use std::array;

    use super::*;

    #[test]
    fn large_array_dont_overflow_stack() {
        // just ensure that these dont panic on construction
        let _deposit_sighashes: DepositSighashes = array::from_fn(|_| [0; 32]);
        let _completed_signatures: CompletedSignatures = array::from_fn(|_| {
            bitcoin::secp256k1::schnorr::Signature::from_slice(&[0; 64]).expect("64 bytes")
        });
    }
}
