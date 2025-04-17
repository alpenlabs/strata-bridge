use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::{block::Header, params::Params};
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_crypto::verify_schnorr_sig;
use strata_primitives::params::RollupParams;
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::bridge_state::DepositState;

use crate::{
    error::{BridgeProofError, BridgeRelatedTx, ChainStateError},
    tx_info::{extract_valid_chainstate_from_checkpoint, extract_withdrawal_info, WithdrawalInfo},
    BridgeProofInputBorsh, BridgeProofPublicOutput,
};

/// The number of headers after withdrawal fulfillment transaction that must be provided as private
/// input
///
/// TODO: update this once this is fixed
pub const REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX: usize = 30;

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
    if !tx.verify(header) {
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
    peg_out_graph_params: PegOutGraphParams,
) -> Result<BridgeProofPublicOutput, BridgeProofError> {
    // 1a. Extract valid chainstate from checkpoint.
    let (strata_checkpoint_tx, strata_checkpoint_idx) = &input.strata_checkpoint_tx;
    let chainstate = extract_valid_chainstate_from_checkpoint(
        strata_checkpoint_tx.transaction(),
        &rollup_params,
    )?;
    let mut header_vs = chainstate.l1_view().header_vs().clone();

    // 1b. Verify that the checkpoint transaction is included in the provided header chain. Since
    // the checkpoint info relies on witness data, `expect_witness` must be `true`.
    verify_tx_inclusion(
        strata_checkpoint_tx,
        BridgeRelatedTx::StrataCheckpoint,
        headers[*strata_checkpoint_idx],
        true,
    )?;

    // 3a. Extract withdrawal fulfillment info.
    let (withdrawal_fulfillment_tx, withdrawal_fullfillment_idx) = &input.withdrawal_fulfillment_tx;
    let WithdrawalInfo {
        operator_idx,
        deposit_idx,
        deposit_txid,
        withdrawal_address: destination,
        withdrawal_amount: amount,
        ..
    } = extract_withdrawal_info(withdrawal_fulfillment_tx.transaction())?;

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
    let entry = chainstate
        .deposits_table()
        .get_deposit(deposit_idx)
        .ok_or(ChainStateError::DepositNotFound(deposit_idx))?;

    let deposit_txid_in_chainstate = entry.output().outpoint().txid;
    if deposit_txid_in_chainstate != deposit_txid {
        Err(ChainStateError::MismatchedDepositTxid {
            deposit_txid_in_chainstate,
            deposit_txid_in_fulfillment: deposit_txid,
        })?;
    }

    let dispatched_state = match entry.deposit_state() {
        DepositState::Dispatched(dispatched_state) => dispatched_state,
        _ => return Err(ChainStateError::InvalidDepositState.into()),
    };
    let withdrawal = dispatched_state.cmd().withdraw_outputs().first().unwrap();

    // 3d. Ensure that the withdrawal information(operator, destination address and amount) matches
    // with the chain state withdrawal output.
    if operator_idx != dispatched_state.assignee()
        || destination != *withdrawal.destination().to_script()
        || amount + peg_out_graph_params.operator_fee.into() != entry.amt()
    {
        return Err(BridgeProofError::InvalidWithdrawalData);
    }

    // 3e. Ensure that the withdrawal was fulfilled before the deadline
    let withdrawal_fulfillment_height =
        header_vs.last_verified_block.height() as usize + withdrawal_fullfillment_idx;
    if withdrawal_fulfillment_height > dispatched_state.exec_deadline() as usize {
        return Err(BridgeProofError::DeadlineExceeded);
    }

    // 4a. Extract the public key of the operator who did the withdrawal fulfillment
    let operator_pub_key = chainstate
        .operator_table()
        .get_operator(operator_idx)
        // TODO: optimization, maybe use `entry_at_pos` to avoid searching
        // Deferred for now because the number of operators will be small
        .unwrap()
        .wallet_pk();

    // 4b. Verify the signature against the operator pub key in the chain state
    let withdrawal_fulfillment_txid = compute_txid(withdrawal_fulfillment_tx.transaction());
    if !verify_schnorr_sig(
        &input.op_signature,
        &withdrawal_fulfillment_txid,
        operator_pub_key,
    ) {
        return Err(BridgeProofError::InvalidOperatorSignature);
    }

    // 6. Ensure that the transactions are in order
    if strata_checkpoint_idx > withdrawal_fullfillment_idx {
        return Err(BridgeProofError::InvalidTxOrder(
            BridgeRelatedTx::StrataCheckpoint,
            BridgeRelatedTx::WithdrawalFulfillment,
        ));
    }

    // 7. Verify that each provided header follows Bitcoin consensus rules. This step ensures the
    //    headers are internally consistent and continuous.
    let btc_params = Params::new(rollup_params.network);
    for header in &headers {
        header_vs.check_and_update_continuity(header, &btc_params)?;
    }

    // 8. Verify sufficient headers after claim transaction
    let headers_after_withdrawal_fulfillment_tx = headers.len() - *withdrawal_fullfillment_idx;
    if headers_after_withdrawal_fulfillment_tx
        < REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX
    {
        return Err(
            BridgeProofError::InsufficientBlocksAfterWithdrawalFulfillment(
                REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX,
                headers_after_withdrawal_fulfillment_tx,
            ),
        );
    }

    // 8. Construct the proof output.
    let output = BridgeProofPublicOutput {
        deposit_txid: deposit_txid.into(),
        withdrawal_fulfillment_txid,
    };

    Ok(output)
}
