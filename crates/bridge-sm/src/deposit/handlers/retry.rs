use std::sync::Arc;

use crate::deposit::{
    config::DepositSMCfg,
    duties::DepositDuty,
    errors::DSMResult,
    machine::{DSMOutput, DepositSM},
    state::DepositState,
};

impl DepositSM {
    /// Emits retriable duties for the current state.
    pub(crate) fn process_retry_tick(&self, cfg: Arc<DepositSMCfg>) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.context().operator_table().cardinality();
        let duties = match self.state() {
            DepositState::DepositPartialsCollected {
                deposit_transaction,
                ..
            } => vec![DepositDuty::PublishDeposit {
                signed_deposit_transaction: deposit_transaction.clone(),
            }],
            DepositState::Assigned {
                assignee,
                deadline,
                recipient_desc,
                ..
            } if self.context().operator_table().pov_idx() == *assignee => {
                vec![DepositDuty::FulfillWithdrawal {
                    deposit_idx: self.context().deposit_idx(),
                    deadline: *deadline,
                    recipient_desc: recipient_desc.clone(),
                    deposit_amount: cfg.deposit_amount(),
                }]
            }
            DepositState::Fulfilled { assignee, .. }
                if self.context().operator_table().pov_idx() == *assignee =>
            {
                vec![DepositDuty::RequestPayoutNonces {
                    deposit_idx: self.context().deposit_idx(),
                    pov_operator_idx: self.context().operator_table().pov_idx(),
                }]
            }
            DepositState::PayoutNoncesCollected {
                assignee,
                cooperative_payout_tx,
                payout_aggregated_nonce,
                payout_partial_signatures,
                ..
            } if self.context().operator_table().pov_idx() == *assignee
                // HACK: (mukeshdroid) The stricter check would have been to assert that the
                // partials except from the assignee has been collected. The following check that
                // asserts *any* n-1 partials are collected is enough since the assignee should
                // never send their partials for their own good.
                && operator_table_cardinality - 1 == payout_partial_signatures.len() =>
            {
                let ordered_pubkeys = self
                    .context()
                    .operator_table()
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect();

                vec![DepositDuty::PublishPayout {
                    deposit_outpoint: self.context().deposit_outpoint(),
                    agg_nonce: payout_aggregated_nonce.clone(),
                    collected_partials: payout_partial_signatures.clone(),
                    payout_coop_tx: Box::new(cooperative_payout_tx.clone()),
                    ordered_pubkeys,
                    pov_operator_idx: self.context().operator_table().pov_idx(),
                }]
            }
            _ => Vec::new(),
        };

        Ok(DSMOutput::with_duties(duties))
    }
}
