use std::sync::Arc;

use crate::{
    graph::{
        config::GraphSMCfg,
        duties::GraphDuty,
        errors::{GSMError, GSMResult},
        machine::{GSMOutput, GraphSM, generate_game_graph},
        state::GraphState,
    },
    signals::DepositToGraph,
};

impl GraphSM {
    /// Processes a message received from the Deposit State Machine.
    pub(crate) fn process_deposit_signal(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        deposit_message: DepositToGraph,
    ) -> GSMResult<GSMOutput> {
        match deposit_message {
            DepositToGraph::CooperativePayoutFailed {
                assignee,
                deposit_idx,
            } => self.process_coop_payout_failed(cfg, assignee, deposit_idx),
        }
    }

    /// Processes the cooperative payout failure signal from the Deposit SM.
    ///
    /// Sets `coop_payout_failed` to `true` in the `Fulfilled` state and emits a
    /// `PublishClaim` duty if the assignee is the PoV operator.
    fn process_coop_payout_failed(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        assignee: u32,
        deposit_idx: u32,
    ) -> GSMResult<GSMOutput> {
        // Extract context values before the match to avoid borrow conflicts
        let graph_ctx = self.context().clone();

        match self.state_mut() {
            GraphState::Fulfilled {
                graph_data,
                coop_payout_failed,
                ..
            } => {
                *coop_payout_failed = true;

                // Generate the game graph to access the claim tx for duty emission
                let game_graph = generate_game_graph(&cfg, &graph_ctx, *graph_data);

                let duties =
                    if self.context().operator_idx() == self.context().operator_table().pov_idx() {
                        vec![GraphDuty::PublishClaim {
                            claim_tx: game_graph.claim,
                        }]
                    } else {
                        Default::default()
                    };

                Ok(GSMOutput::with_duties(duties))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                DepositToGraph::CooperativePayoutFailed {
                    assignee,
                    deposit_idx,
                }
                .into(),
                None,
            )),
        }
    }
}
