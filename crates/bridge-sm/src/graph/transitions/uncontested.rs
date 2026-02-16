use std::sync::Arc;

use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph2::game_graph::DepositParams;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::GraphDataGeneratedEvent,
    machine::{GSMOutput, GraphSM},
    state::GraphState,
};

impl GraphSM {
    /// Processes the event where graph data has been produced for this graph instance.
    ///
    /// Transitions from [`GraphState::Created`] to [`GraphState::GraphGenerated`].
    /// Emits a [`GraphDuty::VerifyAdaptors`] duty.
    pub(crate) fn process_graph_data(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        graph_data_event: GraphDataGeneratedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Created {
                last_block_height, ..
            } => {
                let deposit_params = DepositParams {
                    game_index: graph_data_event.game_index,
                    claim_funds: graph_data_event.claim_funds,
                    deposit_outpoint: self.context.deposit_outpoint(),
                };
                let game_graph = self.generate_graph(&cfg, deposit_params);

                let cur_operator_idx = self.context.operator_idx();
                let duties: Vec<_> = game_graph
                    .counterproofs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, counterproof_graph)| {
                        let watchtower_idx = i as OperatorIdx;
                        (watchtower_idx != cur_operator_idx).then(|| GraphDuty::VerifyAdaptors {
                            graph_idx: self.context.graph_idx(),
                            watchtower_idx,
                            sighashes: counterproof_graph.counterproof.sighashes(),
                        })
                    })
                    .collect();

                self.state = GraphState::GraphGenerated {
                    last_block_height: *last_block_height,
                    graph_data: deposit_params,
                    graph_summary: game_graph.summarize(),
                };

                Ok(GSMOutput::with_duties(duties))
            }
            GraphState::GraphGenerated { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                graph_data_event.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                graph_data_event.into(),
                None,
            )),
        }
    }
}
