use bitcoin::block::Header;
use strata_primitives::params::RollupParams;
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::{bridge_state::DepositState, l1::get_btc_params};

use crate::{
    error::BridgeProofError,
    tx_info::{extract_checkpoint, extract_claim_info, extract_withdrawal_info},
    BridgeProofInput, BridgeProofOutput,
};

pub fn process_bridge_proof(
    input: BridgeProofInput,
    headers: Vec<Header>,
    rollup_params: RollupParams,
) -> BridgeProofOutput {
    // 1a. Extract checkpoint info
    let (strata_checkpoint_tx, strata_checkpoint_idx) = &input.strata_checkpoint_tx;
    let checkpoint =
        extract_checkpoint(strata_checkpoint_tx.transaction(), &rollup_params.cred_rule)
            .expect("checkpoint is required");

    // 1b. Verify the checkpoint proof is part of the header chain
    assert!(strata_checkpoint_tx.get_witness_tx().is_some());
    assert!(
        strata_checkpoint_tx.verify(headers[*strata_checkpoint_idx]),
        "invalid checkpoint tx: non-inclusion"
    );

    // // 1c. Verify the strata checkpoint proof
    // let public_params_raw =
    //     borsh::to_vec(&checkpoint.get_proof_output()).expect("borsh serialization must not
    // fail"); zkvm.verify_groth16_proof(checkpoint.proof(), &rollup_vk.0, &public_params_raw);

    // 2. Verify the chainstate against the checkpoint that was verified
    assert_eq!(
        input.chain_state.compute_state_root(),
        *checkpoint.batch_info().final_l1_state_hash(),
        "invalid chain state: mismatch from checkpoint tx"
    );

    // 3. Verify that all the headers follow Bitcoin consensus rules
    let mut header_vs = input.header_vs;
    let params = get_btc_params();
    for header in &headers {
        header_vs.check_and_update_continuity(header, &params);
    }

    // 4a. Extract withdrawal fulfillment info
    let (withdrawal_fulfillment_tx, withdrawal_fullfillment_idx) = &input.withdrawal_fulfillment_tx;
    assert!(
        withdrawal_fulfillment_tx.verify(headers[*withdrawal_fullfillment_idx]),
        "invalid withdrawal fulfillment tx: non-inclusion"
    );
    let (operator_idx, address, amount) =
        extract_withdrawal_info(withdrawal_fulfillment_tx.transaction())
            .expect("expected withdrawal fulfillment tx");

    // 4b. Assert that the withdrawal info is in the chainstate
    let entry = input
        .chain_state
        .deposits_table()
        .get_deposit(input.deposit_idx as u32)
        .expect("expect a valid deposit entry");

    let dispatched_state = match entry.deposit_state() {
        DepositState::Dispatched(dispatched_state) => dispatched_state,
        _ => panic!("checkpoint: withdrawal not dispatched for given deposit"),
    };
    let withdrawal = dispatched_state.cmd().withdraw_outputs().first().unwrap();
    if operator_idx != dispatched_state.assignee()
        || address != *withdrawal.dest_addr()
        || amount != entry.amt()
    {
        // TODO: amount might be equal to entry.amt()
        // TODO: verify if this might instead be equal to withdrawal.amt()
        panic!("checkpoint: invalid operator or withdrawal address or amount");
    }

    // 5. Verify the group signing key and it's inclusion
    assert!(
        input.anchor_key_proof.verify(input.anchor_key_root),
        "invalid anchor"
    );

    // 6a. Extract claim tx info
    let (claim_tx, claim_tx_idx) = &input.claim_tx;
    let (anchor_idx, withdrawal_fullfillment_txid) =
        extract_claim_info(claim_tx.transaction()).expect("expected claim tx");

    // 6b. Verify that the claim tx is part of the header chain
    let claim_header = headers[*claim_tx_idx];
    assert!(claim_tx.get_witness_tx().is_some());
    assert!(
        claim_tx.verify(claim_header),
        "invalid claim tx: non-inclusion"
    );

    assert_eq!(
        withdrawal_fullfillment_txid,
        compute_txid(withdrawal_fulfillment_tx.transaction()).into(),
        "invalid claim tx: invalid commitment of withdrawal fulfillment tx"
    );
    assert_eq!(
        anchor_idx,
        input.anchor_key_proof.position(),
        "invalid claim tx: invalid commitment of anchor idx"
    );

    let headers_after_claim_tx = headers.len() - claim_tx_idx;
    BridgeProofOutput {
        deposit_txid: entry.output().outpoint().txid.into(),
        anchor_key_root: input.anchor_key_root,
        anchor_idx,
        claim_ts: claim_header.time,
        headers_after_claim_tx,
    }
}
