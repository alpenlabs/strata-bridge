use std::sync::Arc;

use bitcoin::Txid;
use strata_bridge_primitives::types::{DepositIdx, GraphIdx};

use crate::{
    graph::{
        config::GraphSMCfg,
        duties::GraphDuty,
        errors::{GSMError, GSMResult},
        machine::{GSMOutput, GraphSM, generate_game_graph},
        state::{AbortReason, GraphState},
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
                graph_idx,
            } => self.process_coop_payout_failed(cfg, assignee, graph_idx),
            DepositToGraph::DepositRequestTakenBack {
                deposit_idx,
                takeback_txid,
            } => self.process_deposit_request_taken_back(deposit_idx, takeback_txid),
        }
    }

    /// Processes the user's deposit request takeback signal from the Deposit SM.
    fn process_deposit_request_taken_back(
        &mut self,
        deposit_idx: DepositIdx,
        takeback_txid: Txid,
    ) -> GSMResult<GSMOutput> {
        let event = DepositToGraph::DepositRequestTakenBack {
            deposit_idx,
            takeback_txid,
        };

        if self.context().graph_idx().deposit != deposit_idx {
            return Err(GSMError::invalid_event(
                self.state().clone(),
                event.into(),
                Some("deposit request takeback routed to graph for different deposit".to_string()),
            ));
        }

        match self.state() {
            GraphState::Created { .. }
            | GraphState::GraphGenerated { .. }
            | GraphState::AdaptorsVerified { .. }
            | GraphState::NoncesCollected { .. }
            | GraphState::GraphSigned { .. } => {
                self.state = GraphState::Aborted {
                    claim_txid: self.state.claim_txid(),
                    reason: AbortReason::DepositRequestTakenBack {
                        spending_txid: takeback_txid,
                    },
                };
                Ok(GSMOutput::new())
            }
            state @ GraphState::Aborted {
                reason:
                    AbortReason::DepositRequestTakenBack {
                        spending_txid: prior_txid,
                    },
                ..
            } if *prior_txid == takeback_txid => {
                Err(GSMError::duplicate(state.clone(), event.into()))
            }
            state => Err(GSMError::invalid_event(
                state.clone(),
                event.into(),
                Some(
                    "deposit request takeback after graph left pre-assignment requires explicit \
                     reorg recovery"
                        .to_string(),
                ),
            )),
        }
    }

    /// Processes the cooperative payout failure signal from the Deposit SM.
    ///
    /// Sets `coop_payout_failed` to `true` in the `Fulfilled` state and emits a
    /// `PublishClaim` duty if this graph belongs to the PoV operator.
    fn process_coop_payout_failed(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        assignee: u32,
        graph_idx: GraphIdx,
    ) -> GSMResult<GSMOutput> {
        // Extract context values before the match to avoid borrow conflicts
        let graph_ctx = self.context().clone();
        let event = DepositToGraph::CooperativePayoutFailed {
            assignee,
            graph_idx,
        };

        match self.state_mut() {
            GraphState::Fulfilled {
                graph_data,
                coop_payout_failed,
                ..
            } => {
                *coop_payout_failed = true;

                // Generate the game graph to access the claim tx for duty emission
                let game_graph = generate_game_graph(&cfg, &graph_ctx, graph_data);

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
            state @ (GraphState::Claimed { .. }
            | GraphState::Contested { .. }
            | GraphState::BridgeProofPosted { .. }
            | GraphState::BridgeProofTimedout { .. }
            | GraphState::CounterProofPosted { .. }
            | GraphState::AllNackd { .. }
            | GraphState::Acked { .. }
            | GraphState::Withdrawn { .. }
            | GraphState::Slashed { .. }
            | GraphState::Aborted { .. }) => Err(GSMError::rejected(
                state.clone(),
                event.into(),
                "stale cooperative payout failure after graph left Fulfilled",
            )),
            state => Err(GSMError::invalid_event(state.clone(), event.into(), None)),
        }
    }
}
