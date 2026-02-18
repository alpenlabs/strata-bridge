//! [`TxClassifier`] implementation for [`DepositSM`].

use bitcoin::Transaction;
use strata_bridge_primitives::types::BitcoinBlockHeight;

use crate::{
    deposit::{
        events::{
            DepositConfirmedEvent, DepositEvent, FulfillmentConfirmedEvent, PayoutConfirmedEvent,
            UserTakeBackEvent,
        },
        machine::DepositSM,
        state::DepositState,
    },
    tx_classifier::{TxClassifier, is_deposit_spend, is_fulfillment},
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

        let is_drt_spend = self
            .deposit_request_outpoint()
            .is_some_and(|drt_outpoint| is_deposit_spend(drt_outpoint, tx) && txid != dt_txid);
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
            DepositState::Assigned { recipient_desc, .. }
                if is_fulfillment(
                    config.magic_bytes,
                    self.context().deposit_idx,
                    config.deposit_amount(),
                    config.operator_fee,
                    recipient_desc,
                    tx,
                ) =>
            {
                Some(DepositEvent::FulfillmentConfirmed(
                    FulfillmentConfirmedEvent {
                        fulfillment_transaction: tx.clone(),
                        fulfillment_height: height,
                    },
                ))
            }

            DepositState::Fulfilled { .. } => None, // does not expect any txs
            DepositState::PayoutDescriptorReceived { .. } => None, // does not expect any txs

            // expect payout
            DepositState::PayoutNoncesCollected { .. }
            | DepositState::CooperativePathFailed { .. }
                if is_deposit_spend(self.context().deposit_outpoint, tx) =>
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
