//! # Bridge Proof Crate (Deprecated)
//!
//! **This crate is deprecated and should not be used in new development.**
//!
//! It is retained **only for reference** and will be **removed once the Glock-based bridge proof
//! system is implemented and validated.**
//!
//! ---
//!
//! Historically, this crate provided the functionality needed to prove inclusion and validity of
//! specific Bitcoin transactions for the Strata rollup bridge. It included data structures and
//! logic to:
//!
//! - Verify sequences of Bitcoin block headers and their corresponding transactions.
//! - Validate Strata rollup checkpoints via zero-knowledge proofs.
//! - Prove deposits, claims, and withdrawals between Bitcoin and the Strata rollup.
//!
//! With the transition to the Glock-based bridge proof architecture, this implementation is now
//! obsolete and preserved solely for reference during the migration.

mod error;
mod program;
mod statement;

use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::{block::Header, consensus::deserialize};
use borsh::{BorshDeserialize, BorshSerialize};
use statement::process_bridge_proof;
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_params::RollupParams;
use strata_primitives::buf::{Buf32, Buf64};
use zkaleido::ZkVmEnv;

/// Represents the private inputs required by the `BridgeProver` to generate a proof.
///
/// Unlike [`BridgeProofPublicOutput`], which consists of publicly verifiable parameters,
/// this structure contains the confidential data necessary for proof generation.
/// These private inputs are only known to the prover and are not part of the publicly
/// accessible proof validation process.
#[derive(Debug, Clone)]
pub struct BridgeProofInput {
    /// The [RollupParams] of the strata rollup
    pub rollup_params: RollupParams,

    /// The [`PegOutGraphParams`] of the peg-out graph.
    pub pegout_graph_params: PegOutGraphParams,

    /// Vector of Bitcoin headers starting after the one that has been verified by the `header_vs`
    pub headers: Vec<Header>,

    /// The index of the deposit within the `Chainstate` deposit table.
    /// Must match the corresponding information in the withdrawal fulfillment transaction.
    pub deposit_idx: u32,

    /// Transaction (and its inclusion proof) containing the strata checkpoint proof.
    /// The `usize` represents the position of this transaction in the header chain.
    pub strata_checkpoint_tx: (L1TxWithProofBundle, usize),

    /// Transaction (and its inclusion proof) fulfilling the withdrawal.
    /// The `usize` represents the position of this transaction in the header chain.
    pub withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),

    /// Signature of the operator to prove that the withdrawal info was indeed performed
    pub op_signature: Buf64,
}

/// Subset of [`BridgeProofInput`] that is [borsh]-serializable
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct BridgeProofInputBorsh {
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),
    op_signature: Buf64,
}

impl From<BridgeProofInput> for BridgeProofInputBorsh {
    fn from(input: BridgeProofInput) -> Self {
        Self {
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
pub struct BridgeProofPublicOutput {
    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Buf32,
    /// The transaction ID of the withdrawal fulfillment transaction.
    pub withdrawal_fulfillment_txid: Buf32,
}

/// Processes the bridge proof by reading necessary data from the provided ZkVM environment,
/// verifying the included Strata checkpoint proof, and committing the resulting proof output.
///
/// This function is designed for use inside a guest ZkVM program and will **panic** if any
/// errors occur during deserialization, proof verification, or output commitment.
pub fn process_bridge_proof_outer(zkvm: &impl ZkVmEnv) {
    let rollup_params: RollupParams = zkvm.read_serde();
    let pegout_graph_params: PegOutGraphParams = zkvm.read_serde();

    let raw_headers = zkvm.read_buf();
    let headers: Vec<_> = raw_headers
        .chunks_exact(80)
        .map(|chunk| {
            deserialize::<Header>(chunk)
                .expect("Failed to deserialize bitcoin header from 80-byte chunk")
        })
        .collect();

    let input: BridgeProofInputBorsh = zkvm.read_borsh();

    let output = process_bridge_proof(input, headers, rollup_params, pegout_graph_params)
        .expect("expect output");

    zkvm.commit_borsh(&output);
}

pub use program::{get_native_host, BridgeProgram};
pub use statement::REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX;
