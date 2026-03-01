use std::{collections::BTreeSet, sync::Arc};

use strata_bridge_primitives::types::OperatorIdx;

use crate::deposit::{
    config::DepositSMCfg,
    duties::{DepositDuty, NagDuty},
    errors::DSMResult,
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
}
