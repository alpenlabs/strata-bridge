use std::sync::Arc;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::RetryTickEvent,
    machine::{GSMOutput, GraphSM, generate_game_graph},
    state::GraphState,
};

impl GraphSM {
    /// Emits retriable duties for the current state.
    pub(crate) fn process_retry_tick(&self, cfg: Arc<GraphSMCfg>) -> GSMResult<GSMOutput> {
        let duties = match self.state() {
            GraphState::GraphGenerated { graph_data, .. }
                if self.context().operator_idx() != self.context().operator_table().pov_idx() =>
            {
                let game_graph = generate_game_graph(&cfg, self.context(), *graph_data);
                let pov_operator_idx = self.context().operator_table().pov_idx();
                let pov_counterproof_idx = if self.context().operator_idx() <= pov_operator_idx {
                    pov_operator_idx - 1
                } else {
                    pov_operator_idx
                };

                let pov_counterproof_graph = game_graph
                    .counterproofs
                    .get(pov_counterproof_idx as usize)
                    .ok_or_else(|| {
                        GSMError::rejected(
                            self.state().clone(),
                            RetryTickEvent.into(),
                            format!("Missing counterproof for watchtower {pov_operator_idx}"),
                        )
                    })?;

                vec![GraphDuty::VerifyAdaptors {
                    graph_idx: self.context().graph_idx(),
                    watchtower_idx: pov_operator_idx,
                    sighashes: pov_counterproof_graph.counterproof.sighashes(),
                }]
            }
            GraphState::Fulfilled {
                graph_data,
                coop_payout_failed,
                assignee,
                ..
            } if *coop_payout_failed
                && self.context().operator_idx() == self.context().operator_table().pov_idx()
                && self.context().operator_idx() == *assignee =>
            {
                let game_graph = generate_game_graph(&cfg, self.context(), *graph_data);

                vec![GraphDuty::PublishClaim {
                    claim_tx: game_graph.claim,
                }]
            }
            GraphState::Claimed {
                fulfillment_txid, ..
            } if fulfillment_txid.is_none() => {
                // TODO: <https://atlassian.alpenlabs.net/browse/STR-2192>
                // Implement the faulty cases in `process_claim`; this emits `PublishContest`.
                Vec::new()
            }
            GraphState::Contested { .. } => {
                // TODO: <https://atlassian.alpenlabs.net/browse/STR-2675>
                // Implement the `GraphEvent::ContestConfirmed` match arm in
                // `GraphSM::process_event`; this emits `PublishBridgeProof`.
                Vec::new()
            }
            GraphState::BridgeProofPosted { .. } => {
                // TODO: <https://atlassian.alpenlabs.net/browse/STR-2676>
                // Implement the `GraphEvent::BridgeProofConfirmed` match arm in
                // `GraphSM::process_event`; this emits `PublishCounterProof`.
                Vec::new()
            }
            GraphState::CounterProofPosted { .. } => {
                // TODO: <https://atlassian.alpenlabs.net/browse/STR-2677>
                // Implement the `GraphEvent::CounterProofConfirmed` match arm in
                // `GraphSM::process_event`; this emits `PublishCounterProofNack`.
                Vec::new()
            }
            _ => Vec::new(),
        };

        Ok(GSMOutput::with_duties(duties))
    }
}
