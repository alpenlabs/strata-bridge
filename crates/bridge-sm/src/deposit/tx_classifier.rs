//! [`TxClassifier`] implementation for [`DepositSM`].

use bitcoin::Transaction;
use strata_asm_common::TxInputRef;
use strata_asm_txs_bridge_v1::withdrawal_fulfillment::parse_withdrawal_fulfillment_tx;
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_l1_txfmt::ParseConfig;

use crate::{
    deposit::{
        events::{
            DepositConfirmedEvent, DepositEvent, FulfillmentConfirmedEvent, PayoutConfirmedEvent,
            UserTakeBackEvent,
        },
        machine::DepositSM,
        state::DepositState,
    },
    tx_classifier::TxClassifier,
};

impl TxClassifier for DepositSM {
    fn classify_tx(
        &self,
        config: &Self::Config,
        tx: &Transaction,
        height: BitcoinBlockHeight,
    ) -> Option<Self::Event> {
        let txid = tx.compute_txid();
        let dt_txid = self.context().deposit_outpoint().txid;

        let is_drt_spend = self.deposit_request_outpoint().is_some_and(|drt_outpoint| {
            tx.input.iter().any(|input| {
                input.previous_output == drt_outpoint // spends DRT
                    && txid != dt_txid // but is not DT
            })
        });
        if is_drt_spend {
            return Some(DepositEvent::UserTakeBack(UserTakeBackEvent {
                tx: tx.clone(),
            }));
        }

        match self.state() {
            // initial states expect DRT spend but that is handled above.
            DepositState::Created { .. } => None,
            DepositState::GraphGenerated { .. } => None,

            // expect deposit confirmation
            DepositState::DepositNoncesCollected { .. }
            | DepositState::DepositPartialsCollected { .. }
                if txid == dt_txid =>
            {
                Some(DepositEvent::DepositConfirmed(DepositConfirmedEvent {
                    deposit_transaction: tx.clone(),
                }))
            }

            DepositState::Deposited { .. } => None, // does not expect any txs

            // expects fulfillment
            DepositState::Assigned { .. } => {
                let parser = ParseConfig::new(config.magic_bytes);
                let tag_data = parser.try_parse_tx(tx).ok()?;
                let tx_input_ref = TxInputRef::new(tx, tag_data);

                parse_withdrawal_fulfillment_tx(&tx_input_ref)
                    .ok()
                    .and_then(|fulfillment_info| {
                        if fulfillment_info.header_aux().deposit_idx()
                            == self.context().deposit_idx()
                        {
                            Some(DepositEvent::FulfillmentConfirmed(
                                FulfillmentConfirmedEvent {
                                    fulfillment_transaction: tx.clone(),
                                    fulfillment_height: height,
                                },
                            ))
                        } else {
                            None
                        }
                    })
            }

            DepositState::Fulfilled { .. } => None, // does not expect any txs
            DepositState::PayoutDescriptorReceived { .. } => None, // does not expect any txs

            // expect payout
            DepositState::PayoutNoncesCollected { .. }
            | DepositState::CooperativePathFailed { .. }
                if tx
                    .input
                    .iter()
                    .any(|input| input.previous_output == self.context().deposit_outpoint()) =>
            {
                Some(DepositEvent::PayoutConfirmed(PayoutConfirmedEvent {
                    tx: tx.clone(),
                }))
            }

            // terminal states expect no txs
            DepositState::Spent => None,
            DepositState::Aborted => None,

            _ => None,
        }
    }
}
