use std::{collections::BTreeSet, sync::Arc};

use musig2::{AggNonce, secp256k1::Message};
use strata_bridge_p2p_types::NagRequestPayload;
use strata_bridge_primitives::scripts::taproot::TaprootTweak;

use crate::graph::{
    config::GraphSMCfg,
    duties::{GraphDuty, NagDuty},
    errors::{GSMError, GSMResult},
    events::{GraphEvent, NagReceivedEvent},
    machine::{GSMOutput, GraphSM, generate_game_graph},
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

    /// Processes an incoming nag from another operator.
    ///
    /// NOTE: Sender validation, recipient check, and graph_idx routing are done upstream.
    pub(crate) fn process_nag_received(
        &self,
        cfg: Arc<GraphSMCfg>,
        event: NagReceivedEvent,
    ) -> GSMResult<GSMOutput> {
        let duties = match &event.payload {
            NagRequestPayload::GraphData { .. } => self.process_graph_data_nag(&event),
            NagRequestPayload::GraphNonces { .. } => self.process_graph_nonces_nag(&cfg, &event),
            NagRequestPayload::GraphPartials { .. } => {
                self.process_graph_partials_nag(&cfg, &event)
            }
            NagRequestPayload::DepositNonce { .. }
            | NagRequestPayload::DepositPartial { .. }
            | NagRequestPayload::PayoutNonce { .. }
            | NagRequestPayload::PayoutPartial { .. } => {
                Err(self.reject_nag(&event, "Deposit-domain nag is not applicable to GraphSM"))
            }
        }?;

        Ok(GSMOutput::with_duties(duties))
    }

    fn reject_nag(&self, event: &NagReceivedEvent, detail: impl Into<String>) -> GSMError {
        let reason = format!(
            "{}; payload={:?}; sender_operator_idx={}; current_state={}",
            detail.into(),
            event.payload,
            event.sender_operator_idx,
            self.state()
        );

        GSMError::rejected(
            self.state().clone(),
            GraphEvent::NagReceived(event.clone()),
            reason,
        )
    }

    fn process_graph_data_nag(&self, event: &NagReceivedEvent) -> GSMResult<Vec<GraphDuty>> {
        match self.state() {
            GraphState::Created { .. }
            | GraphState::GraphGenerated { .. }
            | GraphState::AdaptorsVerified { .. } => Ok(vec![GraphDuty::GenerateGraphData {
                graph_idx: self.context().graph_idx(),
            }]),
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag GraphData in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable GraphData nag; expected state(s): Created | GraphGenerated | AdaptorsVerified",
                ))
            }
        }
    }

    fn process_graph_nonces_nag(
        &self,
        cfg: &Arc<GraphSMCfg>,
        event: &NagReceivedEvent,
    ) -> GSMResult<Vec<GraphDuty>> {
        match self.state() {
            GraphState::AdaptorsVerified { graph_data, .. }
            | GraphState::NoncesCollected { graph_data, .. } => {
                Ok(vec![self.build_publish_graph_nonces_duty(cfg, *graph_data)])
            }
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag GraphNonces in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable GraphNonces nag; expected state(s): AdaptorsVerified | NoncesCollected",
                ))
            }
        }
    }

    fn process_graph_partials_nag(
        &self,
        cfg: &Arc<GraphSMCfg>,
        event: &NagReceivedEvent,
    ) -> GSMResult<Vec<GraphDuty>> {
        match self.state() {
            GraphState::NoncesCollected {
                graph_data,
                agg_nonces,
                ..
            }
            | GraphState::GraphSigned {
                graph_data,
                agg_nonces,
                ..
            } => Ok(vec![self.build_publish_graph_partials_duty(
                cfg,
                *graph_data,
                agg_nonces.clone(),
            )]),
            _ => {
                tracing::debug!(
                    "Rejecting inapplicable nag GraphPartials in state {}",
                    self.state()
                );
                Err(self.reject_nag(
                    event,
                    "Inapplicable GraphPartials nag; expected state(s): NoncesCollected | GraphSigned",
                ))
            }
        }
    }

    fn build_publish_graph_nonces_duty(
        &self,
        cfg: &GraphSMCfg,
        graph_data: strata_bridge_tx_graph::game_graph::DepositParams,
    ) -> GraphDuty {
        let game_graph = generate_game_graph(cfg, self.context(), graph_data);
        let graph_inpoints = game_graph.musig_inpoints().pack();
        let graph_tweaks = game_graph
            .musig_signing_info()
            .pack()
            .iter()
            .map(|m| m.tweak)
            .collect::<Vec<TaprootTweak>>();
        let ordered_pubkeys = self
            .context()
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        GraphDuty::PublishGraphNonces {
            graph_idx: self.context().graph_idx(),
            graph_inpoints,
            graph_tweaks,
            ordered_pubkeys,
        }
    }

    fn build_publish_graph_partials_duty(
        &self,
        cfg: &GraphSMCfg,
        graph_data: strata_bridge_tx_graph::game_graph::DepositParams,
        agg_nonces: Vec<AggNonce>,
    ) -> GraphDuty {
        let game_graph = generate_game_graph(cfg, self.context(), graph_data);
        let graph_inpoints = game_graph.musig_inpoints().pack();
        let claim_txid = game_graph.claim.as_ref().compute_txid();
        let (graph_tweaks, sighashes): (Vec<TaprootTweak>, Vec<Message>) = game_graph
            .musig_signing_info()
            .pack()
            .iter()
            .map(|m| (m.tweak, m.sighash))
            .unzip();
        let ordered_pubkeys = self
            .context()
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        GraphDuty::PublishGraphPartials {
            graph_idx: self.context().graph_idx(),
            agg_nonces,
            sighashes,
            graph_inpoints,
            graph_tweaks,
            claim_txid,
            ordered_pubkeys,
        }
    }
}
