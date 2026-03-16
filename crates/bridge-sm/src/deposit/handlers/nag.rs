use std::{collections::BTreeSet, sync::Arc};

use strata_bridge_p2p_types::NagRequestPayload;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::transactions::PresignedTx;

use crate::deposit::{
    config::DepositSMCfg,
    duties::{DepositDuty, NagDuty},
    errors::{DSMError, DSMResult},
    events::{DepositEvent, NagReceivedEvent},
    machine::{DSMOutput, DepositSM},
    state::DepositState,
};

impl DepositSM {
    /// Emits nag duties for operators who are missing expected data in the current state.
    pub(crate) fn process_nag_tick(&self, _cfg: Arc<DepositSMCfg>) -> DSMResult<DSMOutput> {
        let deposit_idx = self.context().deposit_idx();
        let operator_table = self.context().operator_table();
        let all_operator_ids = operator_table.operator_idxs();

        let duties = match self.state() {
            DepositState::GraphGenerated { pubnonces, .. } => {
                let expected_ids = &all_operator_ids;
                let present_ids: BTreeSet<_> = pubnonces.keys().copied().collect();
                expected_ids
                    .difference(&present_ids)
                    .map(|&operator_idx| {
                        let operator_pubkey = operator_table
                            .idx_to_p2p_key(&operator_idx)
                            .expect("operator idx from table must exist")
                            .clone();
                        DepositDuty::Nag {
                            duty: NagDuty::NagDepositNonce {
                                deposit_idx,
                                operator_idx,
                                operator_pubkey,
                            },
                        }
                    })
                    .collect()
            }
            DepositState::DepositNoncesCollected {
                partial_signatures, ..
            } => {
                let expected_ids = &all_operator_ids;
                let present_ids: BTreeSet<_> = partial_signatures.keys().copied().collect();
                expected_ids
                    .difference(&present_ids)
                    .map(|&operator_idx| {
                        let operator_pubkey = operator_table
                            .idx_to_p2p_key(&operator_idx)
                            .expect("operator idx from table must exist")
                            .clone();
                        DepositDuty::Nag {
                            duty: NagDuty::NagDepositPartial {
                                deposit_idx,
                                operator_idx,
                                operator_pubkey,
                            },
                        }
                    })
                    .collect()
            }
            DepositState::PayoutDescriptorReceived { payout_nonces, .. } => {
                let expected_ids = &all_operator_ids;
                let present_ids: BTreeSet<_> = payout_nonces.keys().copied().collect();
                expected_ids
                    .difference(&present_ids)
                    .map(|&operator_idx| {
                        let operator_pubkey = operator_table
                            .idx_to_p2p_key(&operator_idx)
                            .expect("operator idx from table must exist")
                            .clone();
                        DepositDuty::Nag {
                            duty: NagDuty::NagPayoutNonce {
                                deposit_idx,
                                operator_idx,
                                operator_pubkey,
                            },
                        }
                    })
                    .collect()
            }
            DepositState::PayoutNoncesCollected {
                assignee,
                payout_partial_signatures,
                ..
            } => {
                let expected_ids: BTreeSet<OperatorIdx> = all_operator_ids
                    .iter()
                    .copied()
                    .filter(|id| id != assignee)
                    .collect();
                let present_ids: BTreeSet<OperatorIdx> =
                    payout_partial_signatures.keys().copied().collect();
                expected_ids
                    .difference(&present_ids)
                    .map(|&operator_idx| {
                        let operator_pubkey = operator_table
                            .idx_to_p2p_key(&operator_idx)
                            .expect("operator idx from table must exist")
                            .clone();
                        DepositDuty::Nag {
                            duty: NagDuty::NagPayoutPartial {
                                deposit_idx,
                                operator_idx,
                                operator_pubkey,
                            },
                        }
                    })
                    .collect()
            }
            _ => Vec::new(),
        };

        Ok(DSMOutput::with_duties(duties))
    }

    /// Processes an incoming nag from another operator.
    ///
    /// NOTE: Sender validation, recipient check, and deposit_idx routing are done upstream.
    pub(crate) fn process_nag_received(&self, event: NagReceivedEvent) -> DSMResult<DSMOutput> {
        let duties = match &event.payload {
            NagRequestPayload::DepositNonce { .. } => self.process_deposit_nonce_nag(&event),
            NagRequestPayload::DepositPartial { .. } => self.process_deposit_partial_nag(&event),
            NagRequestPayload::PayoutNonce { .. } => self.process_payout_nonce_nag(&event),
            NagRequestPayload::PayoutPartial { .. } => self.process_payout_partial_nag(&event),
            NagRequestPayload::GraphData { .. }
            | NagRequestPayload::GraphNonces { .. }
            | NagRequestPayload::GraphPartials { .. } => {
                Err(self.reject_nag(&event, "Graph-domain nag is not applicable to DepositSM"))
            }
        }?;

        Ok(DSMOutput::with_duties(duties))
    }

    fn reject_nag(&self, event: &NagReceivedEvent, detail: impl Into<String>) -> DSMError {
        let reason = format!(
            "{}; payload={:?}; sender_operator_idx={}; current_state={}",
            detail.into(),
            event.payload,
            event.sender_operator_idx,
            self.state()
        );

        DSMError::rejected(
            self.state().clone(),
            DepositEvent::NagReceived(event.clone()),
            reason,
        )
    }

    fn process_deposit_nonce_nag(&self, event: &NagReceivedEvent) -> DSMResult<Vec<DepositDuty>> {
        let deposit_idx = self.context().deposit_idx();
        match self.state() {
            DepositState::GraphGenerated {
                deposit_transaction,
                claim_txids,
                ..
            }
            | DepositState::DepositNoncesCollected {
                deposit_transaction,
                claim_txids,
                ..
            } => {
                let drt_tweak = deposit_transaction
                    .signing_info()
                    .first()
                    .expect("deposit transaction must have signing info")
                    .tweak;
                let ordered_pubkeys = self
                    .context()
                    .operator_table()
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect();
                Ok(vec![DepositDuty::PublishDepositNonce {
                    deposit_idx,
                    drt_outpoint: self.context().deposit_outpoint(),
                    claim_txids: claim_txids.values().copied().collect(),
                    ordered_pubkeys,
                    drt_tweak,
                }])
            }
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag DepositNonce in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable DepositNonce nag; expected state(s): GraphGenerated | DepositNoncesCollected",
                ))
            }
        }
    }

    fn process_deposit_partial_nag(&self, event: &NagReceivedEvent) -> DSMResult<Vec<DepositDuty>> {
        let deposit_idx = self.context().deposit_idx();
        match self.state() {
            DepositState::DepositNoncesCollected {
                agg_nonce,
                deposit_transaction,
                claim_txids,
                ..
            } => {
                let signing_info = deposit_transaction
                    .signing_info()
                    .first()
                    .copied()
                    .expect("deposit transaction must have signing info");
                let ordered_pubkeys = self
                    .context()
                    .operator_table()
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect();
                Ok(vec![DepositDuty::PublishDepositPartial {
                    deposit_idx,
                    drt_outpoint: self.context().deposit_outpoint(),
                    claim_txids: claim_txids.values().copied().collect(),
                    signing_info,
                    deposit_agg_nonce: agg_nonce.clone(),
                    ordered_pubkeys,
                }])
            }
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag DepositPartial in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable DepositPartial nag; expected state(s): DepositNoncesCollected",
                ))
            }
        }
    }

    fn process_payout_nonce_nag(&self, event: &NagReceivedEvent) -> DSMResult<Vec<DepositDuty>> {
        let deposit_idx = self.context().deposit_idx();
        match self.state() {
            DepositState::PayoutDescriptorReceived { .. }
            | DepositState::PayoutNoncesCollected { .. } => {
                let ordered_pubkeys = self
                    .context()
                    .operator_table()
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect();
                Ok(vec![DepositDuty::PublishPayoutNonce {
                    deposit_idx,
                    deposit_outpoint: self.context().deposit_outpoint(),
                    ordered_pubkeys,
                }])
            }
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag PayoutNonce in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable PayoutNonce nag; expected state(s): PayoutDescriptorReceived | PayoutNoncesCollected",
                ))
            }
        }
    }

    fn process_payout_partial_nag(&self, event: &NagReceivedEvent) -> DSMResult<Vec<DepositDuty>> {
        let deposit_idx = self.context().deposit_idx();
        match self.state() {
            DepositState::PayoutNoncesCollected {
                assignee,
                cooperative_payout_tx,
                payout_aggregated_nonce,
                ..
            } if self.context().operator_table().pov_idx() != *assignee => {
                let payout_sighash = cooperative_payout_tx
                    .signing_info()
                    .first()
                    .expect("cooperative payout transaction must have signing info")
                    .sighash;
                let ordered_pubkeys = self
                    .context()
                    .operator_table()
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect();
                Ok(vec![DepositDuty::PublishPayoutPartial {
                    deposit_idx,
                    deposit_outpoint: self.context().deposit_outpoint(),
                    payout_sighash,
                    agg_nonce: payout_aggregated_nonce.clone(),
                    ordered_pubkeys,
                }])
            }
            DepositState::PayoutNoncesCollected { assignee, .. } => {
                tracing::debug!(
                    "Rejecting PayoutPartial nag - POV is assignee and cannot publish payout partial"
                );
                Err(self.reject_nag(
                    event,
                    format!(
                        "Inapplicable PayoutPartial nag; POV operator {} is assignee {} and assignee never publishes payout partial",
                        self.context().operator_table().pov_idx(),
                        assignee
                    ),
                ))
            }
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag PayoutPartial in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable PayoutPartial nag; expected state(s): PayoutNoncesCollected with POV != assignee",
                ))
            }
        }
    }
}
