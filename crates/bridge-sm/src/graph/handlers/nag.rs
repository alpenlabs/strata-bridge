use std::{collections::BTreeSet, sync::Arc};

use crate::graph::{
    config::GraphSMCfg,
    duties::{GraphDuty, NagDuty},
    errors::GSMResult,
    machine::{GSMOutput, GraphSM},
    state::GraphState,
};

impl GraphSM {
    /// Emits nag duties for missing data from peers.
    pub(crate) fn process_nag_tick(&self, _cfg: Arc<GraphSMCfg>) -> GSMResult<GSMOutput> {
        let graph_idx = self.context().graph_idx();
        let operator_table = self.context().operator_table();
        let all_operator_ids = operator_table.operator_idxs();

        let duties = match self.state() {
            GraphState::Created { .. } => {
                let operator_idx = self.context().graph_idx().operator;
                let operator_pubkey = operator_table
                    .idx_to_p2p_key(&operator_idx)
                    .expect("graph owner idx must exist in operator table")
                    .clone();
                vec![GraphDuty::Nag {
                    duty: NagDuty::NagGraphData {
                        graph_idx,
                        operator_idx,
                        operator_pubkey,
                    },
                }]
            }
            GraphState::AdaptorsVerified { pubnonces, .. } => {
                let present_ids: BTreeSet<_> = pubnonces.keys().copied().collect();
                all_operator_ids
                    .difference(&present_ids)
                    .map(|&operator_idx| {
                        let operator_pubkey = operator_table
                            .idx_to_p2p_key(&operator_idx)
                            .expect("operator idx from table must exist")
                            .clone();
                        GraphDuty::Nag {
                            duty: NagDuty::NagGraphNonces {
                                graph_idx,
                                operator_idx,
                                operator_pubkey,
                            },
                        }
                    })
                    .collect()
            }
            GraphState::NoncesCollected {
                partial_signatures, ..
            } => {
                let present_ids: BTreeSet<_> = partial_signatures.keys().copied().collect();
                all_operator_ids
                    .difference(&present_ids)
                    .map(|&operator_idx| {
                        let operator_pubkey = operator_table
                            .idx_to_p2p_key(&operator_idx)
                            .expect("operator idx from table must exist")
                            .clone();
                        GraphDuty::Nag {
                            duty: NagDuty::NagGraphPartials {
                                graph_idx,
                                operator_idx,
                                operator_pubkey,
                            },
                        }
                    })
                    .collect()
            }
            _ => Vec::new(),
        };

        Ok(GSMOutput::with_duties(duties))
    }
}
