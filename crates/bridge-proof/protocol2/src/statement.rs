use bitcoin::block::Header;
use strata_crypto::verify_schnorr_sig;
use strata_primitives::params::RollupParams;
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::{batch::BatchCheckpoint, bridge_state::DepositState, l1::get_btc_params};

use crate::{
    error::{BridgeProofError, BridgeRelatedTx, ChainStateError, InvalidClaimInfo},
    tx_inclusion_proof::L1TxWithProofBundle,
    tx_info::{extract_checkpoint, extract_claim_info, extract_withdrawal_info},
    BridgeProofInputBorsh, BridgeProofOutput,
};

/// The number of headers after claim transaction that must be provided as private input
///
/// TODO: update this once this is fixed
const REQUIRED_NUM_OF_HEADERS_AFTER_CLAIM_TX: usize = 30;

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

    // 3a. Extract withdrawal fulfillment info.
    let (withdrawal_fulfillment_tx, withdrawal_fullfillment_idx) = &input.withdrawal_fulfillment_tx;
    let (operator_idx, address, amount) =
        extract_withdrawal_info(withdrawal_fulfillment_tx.transaction())?;

    // 3b. Verify the inclusion of the withdrawal fulfillment transaction in the header chain. The
    // transaction does not depend on witness data, hence `expect_witness` is `false`.
    verify_tx_inclusion(
        withdrawal_fulfillment_tx,
        BridgeRelatedTx::WithdrawalFulfillment,
        headers[*withdrawal_fullfillment_idx],
        false,
    )?;

    // 3c. Extract the withdrawal output from the chain state using the specified
    // deposit index.
    let entry = input
        .chain_state
        .deposits_table()
        .get_deposit(input.deposit_idx)
        .ok_or(ChainStateError::DepositNotFound(input.deposit_idx))?;

    let dispatched_state = match entry.deposit_state() {
        DepositState::Dispatched(dispatched_state) => dispatched_state,
        _ => return Err(ChainStateError::InvalidDepositState.into()),
    };
    let withdrawal = dispatched_state.cmd().withdraw_outputs().first().unwrap();

    // 3d. Ensure that the withdrawal information(operator, destination address and amount) matches
    // with the chain state withdrawal output.
    if operator_idx != dispatched_state.assignee()
        || address != *withdrawal.dest_addr()
        // TODO: amount should be equal to entry.amt() - withdrawal_fee
        // withdrawal_fee will be part of the params
        || amount != entry.amt()
    {
        return Err(BridgeProofError::InvalidWithdrawalData);
    }

    // 3e. Ensure that the withdrawal was fulfilled before the deadline
    let withdrawal_fulfillment_height =
        input.header_vs.last_verified_block_num as usize + withdrawal_fullfillment_idx;
    if withdrawal_fulfillment_height > dispatched_state.exec_deadline() as usize {
        return Err(BridgeProofError::DeadlineExceeded);
    }

    // 4a. Extract the public key of the operator who did the withdrawal fulfillment
    let operator_pub_key = input
        .chain_state
        .operator_table()
        .get_operator(operator_idx)
        // TODO: optimization, maybe use `entry_at_pos` to avoid searching
        // Deferred for now because the number of operators will be small
        .unwrap()
        .signing_pk();

    // 4b. Verify the signature against the operator pub key in the chain state
    // TODO: verifying the signature of the withdrawal fulfillment transaction is sufficient or
    // should be message include some other information as well
    let msg = compute_txid(withdrawal_fulfillment_tx.transaction());
    if !verify_schnorr_sig(&input.op_signature, &msg, operator_pub_key) {
        return Err(BridgeProofError::InvalidSignature);
    }

    // 5a. Extract claim transaction info: anchor index and withdrawal fulfillment txid.
    let (claim_tx, claim_tx_idx) = &input.claim_tx;
    let withdrawal_fullfillment_txid = extract_claim_info(claim_tx.transaction())?;

    // 5b. Verify the inclusion of the claim transaction in the header chain. The claim depends on
    // witness data, so we expect witness to be present.
    verify_tx_inclusion(
        claim_tx,
        BridgeRelatedTx::Claim,
        headers[*claim_tx_idx],
        true,
    )?;

    // 6c. Check that the claim's recorded withdrawal fulfillment TXID matches the actual TXID of
    // the withdrawal fulfillment transaction.
    if withdrawal_fullfillment_txid != compute_txid(withdrawal_fulfillment_tx.transaction()).into()
    {
        return Err(InvalidClaimInfo::InvalidWithdrawalCommitment.into());
    }

    // 6. Ensure that the transactions are in order
    if strata_checkpoint_idx > withdrawal_fullfillment_idx {
        return Err(BridgeProofError::InvalidTxOrder(
            BridgeRelatedTx::StrataCheckpoint,
            BridgeRelatedTx::WithdrawalFulfillment,
        ));
    }
    if withdrawal_fullfillment_idx > claim_tx_idx {
        return Err(BridgeProofError::InvalidTxOrder(
            BridgeRelatedTx::WithdrawalFulfillment,
            BridgeRelatedTx::Claim,
        ));
    }

    // 7. Verify that each provided header follows Bitcoin consensus rules. This step ensures the
    //    headers are internally consistent and continuous.
    let mut header_vs = input.header_vs;
    let params = get_btc_params();
    for header in &headers {
        // NOTE: This may panic internally on failure, which should be handled appropriately.
        header_vs.check_and_update_continuity(header, &params);
    }

    // 8. Verify sufficient headers after claim transaction
    let headers_after_claim_tx = headers.len() - claim_tx_idx;
    if REQUIRED_NUM_OF_HEADERS_AFTER_CLAIM_TX < headers_after_claim_tx {
        return Err(BridgeProofError::InsufficientBlocksAfterClaim(
            REQUIRED_NUM_OF_HEADERS_AFTER_CLAIM_TX,
            headers_after_claim_tx,
        ));
    }

    // 8. Construct the proof output.
    let output = BridgeProofOutput {
        deposit_txid: entry.output().outpoint().txid.into(),
        withdrawal_txid: withdrawal_fullfillment_txid.into(),
    };

    Ok((output, checkpoint))
}
