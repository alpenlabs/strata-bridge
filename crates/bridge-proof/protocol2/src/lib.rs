//! # Bridge Proof Crate
//!
//! This crate provides the functionality necessary to prove the inclusion and validity of specific
//! Bitcoin transactions as part of the Strata rollup bridge. It contains data structures and logic
//! to:
//!
//! - Verify sequences of Bitcoin block headers and their corresponding transactions.
//! - Validate checkpoints for the Strata rollup via zero-knowledge proofs.
//! - Prove deposits, claims, and withdrawals between Bitcoin and the Strata rollup.

mod error;
mod prover;
mod statement;
mod test_data;
mod tx;
mod tx_inclusion_proof;
mod tx_info;

use bitcoin::{block::Header, consensus::deserialize};
use borsh::{BorshDeserialize, BorshSerialize};
use statement::process_bridge_proof;
use strata_primitives::{
    buf::{Buf32, Buf64},
    params::RollupParams,
    proof::RollupVerifyingKey,
};
use strata_state::{chain_state::Chainstate, l1::HeaderVerificationState};
use tx_inclusion_proof::L1TxWithProofBundle;
use zkaleido::ZkVmEnv;

/// Represents the private inputs required by the `BridgeProver` to generate a proof.
///
/// Unlike [`BridgeProofOutput`], which consists of publicly verifiable parameters,
/// this structure contains the confidential data necessary for proof generation.
/// These private inputs are only known to the prover and are not part of the publicly
/// accessible proof validation process.
#[derive(Debug, Clone)]
pub struct BridgeProofInput {
    /// The [RollupParams] of the strata rollup
    rollup_params: RollupParams,

    /// Vector of Bitcoin headers starting after the one that has been verified by the `header_vs`
    headers: Vec<Header>,

    /// The [Chainstate] that can be verified by the strata checkpoint proof.
    chain_state: Chainstate,

    /// The [HeaderVerificationState] used to validate the chain of headers.  
    /// The proof that this HeaderVerificationState is valid must be done extracted from the
    /// `strata_checkpoint_tx`.
    header_vs: HeaderVerificationState,

    /// The index of the deposit within the [Chainstate] deposit table.  
    /// Must match the corresponding information in the withdrawal fulfillment transaction.
    deposit_idx: u32,

    /// Transaction (and its inclusion proof) containing the strata checkpoint proof.  
    /// The `usize` represents the position of this transaction in the header chain.
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),

    /// Transaction (and its inclusion proof) fulfilling the withdrawal.  
    /// The `usize` represents the position of this transaction in the header chain.
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),

    /// Signature of the operator to prove that the withdrawal info was indeed performed
    op_signature: Buf64,
}

/// Subset of [`BridgeProofInput`] that is [borsh]-serializable
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct BridgeProofInputBorsh {
    chain_state: Chainstate,
    header_vs: HeaderVerificationState,
    deposit_idx: u32,
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),
    op_signature: Buf64,
}

impl From<BridgeProofInput> for BridgeProofInputBorsh {
    fn from(input: BridgeProofInput) -> Self {
        Self {
            chain_state: input.chain_state,
            header_vs: input.header_vs,
            deposit_idx: input.deposit_idx,
            strata_checkpoint_tx: input.strata_checkpoint_tx,
            withdrawal_fulfillment_tx: input.withdrawal_fulfillment_tx,
            op_signature: input.op_signature,
        }
    }
}

/// Represents the public outputs of the `BridgeProver`, used for proof verification.
///
/// Unlike [`BridgeProofInput`], which contains private inputs required for generating a proof,
/// this structure holds publicly accessible data necessary for validating the proof statements.
/// These outputs, also known as public inputs/outputs or public parameters, are used to verify
/// the correctness of the proof without revealing confidential details.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BridgeProofOutput {
    /// The transaction ID of the deposit transaction.
    deposit_txid: Buf32,
    /// The transaction ID of the withdrawal fulfillment transaction.
    withdrawal_txid: Buf32,
}

/// Processes the bridge proof by reading necessary data from the provided ZkVM environment,
/// verifying the included Strata checkpoint proof, and committing the resulting proof output.
///
/// This function is designed for use inside a guest ZkVM program and will **panic** if any
/// errors occur during deserialization, proof verification, or output commitment.
pub fn process_bridge_proof_outer(zkvm: &impl ZkVmEnv) {
    let rollup_params: RollupParams = zkvm.read_serde();

    let raw_headers = zkvm.read_buf();
    let headers: Vec<_> = raw_headers
        .chunks_exact(80)
        .map(|chunk| {
            deserialize::<Header>(chunk)
                .expect("Failed to deserialize bitcoin header from 80-byte chunk")
        })
        .collect();

    // TODO: update the strata_primitives?
    let rollup_vk = match rollup_params.rollup_vk() {
        RollupVerifyingKey::SP1VerifyingKey(sp1_vk) => sp1_vk,
        RollupVerifyingKey::Risc0VerifyingKey(risc0_vk) => risc0_vk,
        RollupVerifyingKey::NativeVerifyingKey(native_vk) => native_vk,
    };

    let input: BridgeProofInputBorsh = zkvm.read_borsh();

    let (output, checkpoint) =
        process_bridge_proof(input, headers, rollup_params).expect("expect output");

    // Verify the strata checkpoint proof
    zkvm.verify_groth16_receipt(&checkpoint.into_proof_receipt(), &rollup_vk.0);

    zkvm.commit_borsh(&output);
}

pub use prover::BridgeProver;
