mod protocol_op;
mod signing_key_proof;
mod tx_inclusion_proof;

use bitcoin::{block::Header, Transaction};
use protocol_op::extract_checkpoint;
use signing_key_proof::AnchorPublicKeyMerkleProof;
use strata_primitives::{buf::Buf32, params::RollupParams};
use strata_state::{
    batch::{BatchCheckpoint, SignedBatchCheckpoint},
    chain_state::Chainstate,
};
use strata_tx_parser::inscription::parse_inscription_data;
use tx_inclusion_proof::L1TxWithProofBundle;

pub struct BridgeProofInput {
    /// Chain of bitcoin headers
    ///
    /// The first header is the block till where the strata checkpoint verifies the
    /// headerverification state
    /// i.e. if the strata checkpoint verifies till bitcoin block 100. the first header is the
    /// header of the block 101
    headers: Vec<Header>,
    /// Chainstate that can be verified by the strata checkpoint proof
    chain_state: Chainstate,
    deposit_idx: usize,
    /// inclusion proof of the transaction that contains the strata checkpoint proof.
    /// the second usize represents where the transaction is placed in the header chain.
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),
    claim_tx: (L1TxWithProofBundle, usize),
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),
    anchor_key_proof: AnchorPublicKeyMerkleProof,
    rollup_params: RollupParams,
}

pub struct BridgeProofOutput {
    anchor_idx: usize,
    anchor_key_root: Buf32,
    deposit_txid: Buf32,
}

pub fn process_bridge_proof(input: &BridgeProofInput) {
    // 1. Extract checkpoint info
    let (strata_checkpoint_tx, strata_checkpoint_idx) = &input.strata_checkpoint_tx;
    let checkpoint = extract_checkpoint(
        strata_checkpoint_tx.transaction(),
        &input.rollup_params.cred_rule,
    )
    .expect("checkpoint is required");
}
