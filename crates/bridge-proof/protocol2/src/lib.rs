mod protocol_op;
mod signing_key_proof;
mod tx;
mod tx_inclusion_proof;

use bitcoin::{block::Header, consensus::deserialize};
use borsh::{BorshDeserialize, BorshSerialize};
use protocol_op::extract_checkpoint;
use secp256k1::serde::Serialize;
use signing_key_proof::AnchorPublicKeyMerkleProof;
use strata_primitives::{buf::Buf32, params::RollupParams, proof::RollupVerifyingKey};
use strata_state::{
    batch::BatchCheckpoint,
    chain_state::Chainstate,
    l1::{get_btc_params, HeaderVerificationState},
};
use strata_zkvm::ZkVmEnv;
use tx_inclusion_proof::L1TxWithProofBundle;

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BridgeProofInput {
    /// Chainstate that can be verified by the strata checkpoint proof
    chain_state: Chainstate,
    header_vs: HeaderVerificationState,
    deposit_idx: usize,
    /// inclusion proof of the transaction that contains the strata checkpoint proof.
    /// the second usize represents where the transaction is placed in the header chain.
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),
    claim_tx: (L1TxWithProofBundle, usize),
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),
    anchor_key_proof: AnchorPublicKeyMerkleProof,
}

pub struct BridgeProofOutput {
    anchor_idx: usize,
    anchor_key_root: Buf32,
    deposit_txid: Buf32,
}

pub fn process_bridge_proof(zkvm: &impl ZkVmEnv) {
    let rollup_params: RollupParams = zkvm.read_serde();

    let raw_headers = zkvm.read_buf();
    let headers: Vec<_> = raw_headers
        .chunks_exact(80)
        .map(|chunk| {
            deserialize::<Header>(chunk)
                .expect("Failed to deserialize bitcoin header from 80-byte chunk")
        })
        .collect();

    // TODO: update the primitives
    let rollup_vk = match rollup_params.rollup_vk() {
        RollupVerifyingKey::SP1VerifyingKey(sp1_vk) => sp1_vk,
        RollupVerifyingKey::Risc0VerifyingKey(risc0_vk) => risc0_vk,
        RollupVerifyingKey::NativeVerifyingKey(native_vk) => native_vk,
    };

    let input: BridgeProofInput = zkvm.read_borsh();

    // 1. Extract checkpoint info
    let (strata_checkpoint_tx, strata_checkpoint_idx) = &input.strata_checkpoint_tx;
    let checkpoint =
        extract_checkpoint(strata_checkpoint_tx.transaction(), &rollup_params.cred_rule)
            .expect("checkpoint is required");

    // 2. Verify the strata checkpoint proof
    let public_params_raw =
        borsh::to_vec(&checkpoint.get_proof_output()).expect("borsh serialization must not fail");
    zkvm.verify_groth16_proof(checkpoint.proof(), &rollup_vk.0, &public_params_raw);

    // 3. Verify the checkpoint proof is part of the header chain
    assert!(
        strata_checkpoint_tx.verify(headers[*strata_checkpoint_idx]),
        "checkpoint tx is in given header"
    );

    // 4. Verify the chainstate against the checkpoint that was verified
    assert_eq!(
        input.chain_state.compute_state_root(),
        *checkpoint.batch_info().final_l1_state_hash(),
        "Chain state provided is valid"
    );

    // 5. Verify that all the headers follow Bitcoin consensus rules
    let mut header_vs = input.header_vs;
    let params = get_btc_params();
    for header in &headers {
        header_vs.check_and_update_continuity(header, &params);
    }
}
