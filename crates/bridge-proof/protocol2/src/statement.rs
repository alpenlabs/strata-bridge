use bitcoin::block::Header;
use strata_primitives::params::RollupParams;
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::{batch::BatchCheckpoint, bridge_state::DepositState, l1::get_btc_params};

use crate::{
    error::{BridgeProofError, BridgeRelatedTx, ChainStateError, InvalidClaimInfo},
    tx_inclusion_proof::L1TxWithProofBundle,
    tx_info::{extract_checkpoint, extract_claim_info, extract_withdrawal_info},
    BridgeProofInputBorsh, BridgeProofOutput,
};

/// Verifies that the given transaction is included in the provided Bitcoin header's merkle root.
/// Also optionally checks if the transaction includes witness data.
///
/// # Arguments
///
/// * `tx` - The transaction bundle containing proof information.
/// * `tx_marker` - Identifies the type of transaction (checkpoint, withdrawal, or claim).
/// * `header` - The Bitcoin block header in which the transaction is purportedly included.
/// * `expect_witness` - A boolean indicating whether the transaction must include witness data.
///
/// # Errors
///
/// Returns a `BridgeProofError::InvalidMerkleProof` if:
/// - The witness data is expected but missing.
/// - The merkle proof fails verification against the provided header.
fn verify_tx_inclusion(
    tx: &L1TxWithProofBundle,
    tx_marker: BridgeRelatedTx,
    header: Header,
    expect_witness: bool,
) -> Result<(), BridgeProofError> {
    // If the transaction is expected to carry witness data, ensure it is present.
    if expect_witness && tx.get_witness_tx().is_none() {
        return Err(BridgeProofError::InvalidMerkleProof(tx_marker));
    }

    // Verify the merkle proof against the header. If verification fails, return an error.
    if tx.verify(header) {
        return Err(BridgeProofError::InvalidMerkleProof(tx_marker));
    }

    Ok(())
}

/// Processes the verification of all transactions and chain state necessary for a bridge proof.
///
/// # Arguments
///
/// * `input` - The input data for the bridge proof, containing transactions and state information.
/// * `headers` - A sequence of Bitcoin headers that should include the transactions in question.
/// * `rollup_params` - Configuration parameters for the Strata Rollup.
///
/// # Returns
///
/// If successful, returns a tuple consisting of:
/// - `BridgeProofOutput` containing essential proof-related output data.
/// - `BatchCheckpoint` representing the Strata checkpoint.
pub(crate) fn process_bridge_proof(
    input: BridgeProofInputBorsh,
    headers: Vec<Header>,
    rollup_params: RollupParams,
) -> Result<(BridgeProofOutput, BatchCheckpoint), BridgeProofError> {
    // 1a. Extract checkpoint info.
    let (strata_checkpoint_tx, strata_checkpoint_idx) = &input.strata_checkpoint_tx;
    let checkpoint =
        extract_checkpoint(strata_checkpoint_tx.transaction(), &rollup_params.cred_rule)?;

    // 1b. Verify that the checkpoint transaction is included in the provided header chain. Since
    // the checkpoint info relies on witness data, `expect_witness` must be `true`.
    verify_tx_inclusion(
        strata_checkpoint_tx,
        BridgeRelatedTx::StrataCheckpoint,
        headers[*strata_checkpoint_idx],
        true,
    )?;

    // 2. Verify that the chain state root matches the checkpoint's state root. This ensures the
    //    provided chain state aligns with the checkpoint data.
    if input.chain_state.compute_state_root() != *checkpoint.batch_info().final_l1_state_hash() {
        return Err(BridgeProofError::ChainStateMismatch);
    }

    // 3. Verify that each provided header follows Bitcoin consensus rules. This step ensures the
    //    headers are internally consistent and continuous.
    let mut header_vs = input.header_vs;
    let params = get_btc_params();
    for header in &headers {
        // NOTE: This may panic internally on failure, which should be handled appropriately.
        header_vs.check_and_update_continuity(header, &params);
    }

    // 4a. Extract withdrawal fulfillment info.
    let (withdrawal_fulfillment_tx, withdrawal_fullfillment_idx) = &input.withdrawal_fulfillment_tx;
    let (operator_idx, address, amount) =
        extract_withdrawal_info(withdrawal_fulfillment_tx.transaction())?;

    // 4b. Verify the inclusion of the withdrawal fulfillment transaction in the header chain. The
    // transaction does not depend on witness data, hence `expect_witness` is `false`.
    verify_tx_inclusion(
        withdrawal_fulfillment_tx,
        BridgeRelatedTx::WithdrawalFulfillment,
        headers[*withdrawal_fullfillment_idx],
        false,
    )?;

    // 4c. Ensure that the withdrawal information aligns with the chain state at the specified
    // deposit index.
    let entry = input
        .chain_state
        .deposits_table()
        .get_deposit(input.deposit_idx as u32)
        .ok_or(ChainStateError::DepositNotFound(input.deposit_idx))?;

    let dispatched_state = match entry.deposit_state() {
        DepositState::Dispatched(dispatched_state) => dispatched_state,
        _ => return Err(ChainStateError::InvalidDepositState.into()),
    };

    // The deposit's assigned operator, destination address, and amount must match
    // what was provided in the withdrawal fulfillment transaction.
    let withdrawal = dispatched_state.cmd().withdraw_outputs().first().unwrap();
    if operator_idx != dispatched_state.assignee()
        || address != *withdrawal.dest_addr()
        // TODO: amount should be equal to entry.amt() - withdrawal_fee
        // withdrawal_fee will be part of the params
        || amount != entry.amt()
    {
        return Err(BridgeProofError::InvalidWithdrawalData);
    }

    // 5a. Extract claim transaction info: anchor index and withdrawal fulfillment txid.
    let (claim_tx, claim_tx_idx) = &input.claim_tx;
    let withdrawal_fullfillment_txid = extract_claim_info(claim_tx.transaction())?;

    // 5b. Verify the inclusion of the claim transaction in the header chain. The claim depends on
    // witness data, so we expect witness to be present.
    let claim_header = headers[*claim_tx_idx];
    verify_tx_inclusion(claim_tx, BridgeRelatedTx::Claim, claim_header, true)?;

    // 5c. Check that the claim's recorded withdrawal fulfillment TXID matches the actual TXID of
    // the withdrawal fulfillment transaction.
    if withdrawal_fullfillment_txid != compute_txid(withdrawal_fulfillment_tx.transaction()).into()
    {
        return Err(InvalidClaimInfo::InvalidWithdrawalCommitment.into());
    }

    // 6. Construct the proof output.
    let headers_after_claim_tx = headers.len() - claim_tx_idx;
    let output = BridgeProofOutput {
        deposit_txid: entry.output().outpoint().txid.into(),
        claim_ts: claim_header.time,
        headers_after_claim_tx,
    };

    Ok((output, checkpoint))
}
