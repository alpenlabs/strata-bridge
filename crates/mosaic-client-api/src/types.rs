//! Common types for mosaic client

use bitcoin::XOnlyPublicKey;
pub use bitcoin::secp256k1::schnorr::Signature;
pub use mosaic_common::constants::{
    N_DEPOSIT_INPUT_WIRES, N_SETUP_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES,
};
pub use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

/// A Txn sighash to be signed.
pub type Sighash = [u8; 32];
/// Tweak for schnorr signatures
pub type Tweak = [u8; 32];
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

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Garbler => f.write_str("Garbler"),
            Role::Evaluator => f.write_str("Evaluator"),
        }
    }
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
pub struct G16ProofRaw(pub [u8; N_WITHDRAWAL_INPUT_WIRES]);
