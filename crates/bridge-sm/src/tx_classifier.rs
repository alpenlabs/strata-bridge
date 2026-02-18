//! Defines a trait for all state machines to accept transaction IDs and classify them into
//! acceptable events if relevant.

use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitcoin_bosd::Descriptor;
use strata_asm_common::TxInputRef;
use strata_asm_txs_bridge_v1::withdrawal_fulfillment::parse_withdrawal_fulfillment_tx;
use strata_bridge_primitives::types::{BitcoinBlockHeight, DepositIdx, OperatorIdx};
use strata_bridge_tx_graph2::{
    game_graph::GameGraphSummary,
    transactions::{
        claim::ClaimTx,
        prelude::{ContestTx, CounterproofTx},
    },
};
use strata_l1_txfmt::{MagicBytes, ParseConfig};

use crate::state_machine::StateMachine;

/// Classifies raw Bitcoin transactions into typed State Machine Events.
///
/// Implementers use their own internal state (known txids, graph summaries,
/// current state, etc.) to decide relevance and produce the correct event variant
/// in a single pass.
pub trait TxClassifier: StateMachine {
    /// Classifies a transaction ID into an event if relevant to this state machine.
    ///
    /// Returns `None` if the transaction is not relevant to this state machine, or `Some(event)` if
    /// it is.
    fn classify_tx(
        &self,
        config: &Self::Config,
        tx: &Transaction,
        height: BitcoinBlockHeight,
    ) -> Option<Self::Event>;
}

// ------- Predicates for classifying transactions into events -------

/// Checks if the transaction is a fulfillment for the given deposit index.
pub fn is_fulfillment(
    magic_bytes: MagicBytes,
    deposit_idx: DepositIdx,
    deposit_amount: Amount,
    recipient: &Descriptor,
    tx: &Transaction,
) -> bool {
    let parser = ParseConfig::new(magic_bytes);
    parser.try_parse_tx(tx).is_ok_and(|tag_data| {
        let tx_input_ref = TxInputRef::new(tx, tag_data);

        parse_withdrawal_fulfillment_tx(&tx_input_ref).is_ok_and(|fulfillment_info| {
            Amount::from(fulfillment_info.withdrawal_amount()) == deposit_amount
                && *fulfillment_info.withdrawal_destination() == recipient.to_script()
                && fulfillment_info.header_aux().deposit_idx() == deposit_idx
        })
    })
}

/// Checks if the transaction spends the deposit outpoint.
pub fn is_deposit_spend(deposit_outpoint: OutPoint, tx: &Transaction) -> bool {
    tx.input
        .iter()
        .any(|input| input.previous_output == deposit_outpoint)
}

/// Checks if the transaction is a bridge proof transaction
///
/// A bridge proof transaction is not presigned (no fixed txid) but it spends the output of the
/// contest transaction at a known vout.
pub fn is_bridge_proof_tx(contest_txid: Txid, tx: &Transaction) -> bool {
    let contest_proof_outpoint = OutPoint {
        txid: contest_txid,
        vout: ContestTx::PROOF_VOUT,
    };
    tx.input
        .iter()
        .any(|input| input.previous_output == contest_proof_outpoint)
}

/// Checks if the transaction ID is that of a counterproof transaction.
pub fn is_counterproof_txid(summary: &GameGraphSummary, txid: &Txid) -> bool {
    summary
        .counterproofs
        .iter()
        .any(|summary| summary.counterproof == *txid)
}

/// Checks if the transaction ID is that of a counterpoof ACK transaction.
pub fn is_counterproof_ack_txid(summary: &GameGraphSummary, txid: &Txid) -> bool {
    summary
        .counterproofs
        .iter()
        .any(|summary| summary.counterproof_ack == *txid)
}

/// Check if the transaction is a counterproof NACK transaction and returns the index of the
/// operator that did the `NACK`-ing.
///
/// A ACK transaction is not presigned but it spends the output of the counterproof.
pub fn is_counterproof_nack_tx(
    summary: &GameGraphSummary,
    pov_idx: OperatorIdx,
    tx: &Transaction,
) -> Option<OperatorIdx> {
    summary
        .counterproofs
        .iter()
        .find_map(|summary| {
            let expected_counteproof_outpoint = OutPoint {
                txid: summary.counterproof,
                vout: CounterproofTx::ACK_NACK_VOUT,
            };

            tx.input.iter().enumerate().find_map(|(input_index, txin)| {
                if txin.previous_output == expected_counteproof_outpoint {
                    Some(input_index as OperatorIdx)
                } else {
                    None
                }
            })
        })
        .map(|output_index| {
            // Counterproof outputs are arranged in order of operator indices
            // so if the output_index is earlier than the pov_idx, it corresponds to the
            // same indexed operator, otherwise it corresponds to the operator at index
            // output_index - 1
            if output_index <= pov_idx {
                output_index
            } else {
                output_index - 1
            }
        })
}

/// Check if the payout connector has been spent (via admin or unstaking burn txs).
pub fn is_payout_connector_spent(claim_txid: &Txid, tx: &Transaction) -> bool {
    let payout_connector_outpoint = OutPoint {
        txid: *claim_txid,
        vout: ClaimTx::PAYOUT_VOUT,
    };

    tx.input
        .iter()
        .any(|input| input.previous_output == payout_connector_outpoint)
}
