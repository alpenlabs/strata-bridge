//! Defines a trait for all state machines to accept transaction IDs and classify them into
//! acceptable events if relevant.

use bitcoin::{Amount, OutPoint, Transaction};
use bitcoin_bosd::Descriptor;
use strata_asm_common::TxInputRef;
use strata_asm_txs_bridge_v1::withdrawal_fulfillment::parse_withdrawal_fulfillment_tx;
use strata_bridge_primitives::types::{BitcoinBlockHeight, DepositIdx};
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

