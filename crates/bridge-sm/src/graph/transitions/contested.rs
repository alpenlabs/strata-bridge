use std::sync::Arc;

use strata_bridge_tx_graph::game_graph::GameConnectors;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::{
        BridgeProofTimeoutConfirmedEvent, ContestConfirmedEvent, CounterProofAckConfirmedEvent,
    },
    machine::{GSMOutput, GraphSM},
    state::GraphState,
    watchtower::watchtower_slot_for_operator,
};

impl GraphSM {
    /// Processes the event where a contest transaction has been confirmed on-chain.
    ///
    /// Only valid from the `Claimed` state transitions to `Contested` state.
    /// Emits a [`GraphDuty::GenerateAndPublishBridgeProof`] duty if the current operator is the
    /// graph owner.
    pub(crate) fn process_contest(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        event: ContestConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state.clone() {
            GraphState::Claimed {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                fulfillment_block_height,
                ..
            } => {
                if event.contest_txid != graph_summary.contest {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "Invalid contest transaction",
                    ));
                }

                self.state = GraphState::Contested {
                    last_block_height,
                    graph_data,
                    graph_summary: graph_summary.clone(),
                    signatures,
                    fulfillment_txid,
                    fulfillment_block_height,
                    contest_block_height: event.contest_block_height,
                };

                // The graph owner must publish a bridge proof to defend against the contest
                let duties =
                    if self.context().operator_idx() == self.context().operator_table().pov_idx() {
                        let setup_params = self.context().generate_setup_params(&cfg);
                        let connectors = GameConnectors::new(
                            graph_data.game_index,
                            &cfg.game_graph_params,
                            &setup_params,
                        );

                        vec![GraphDuty::GenerateAndPublishBridgeProof {
                            graph_idx: self.context().graph_idx(),
                            contest_txid: graph_summary.contest,
                            game_index: graph_data.game_index,
                            contest_proof_connector: connectors.contest_proof,
                        }]
                    } else {
                        Vec::new()
                    };

                Ok(GSMOutput::with_duties(duties))
            }
            state @ GraphState::Contested { .. } => Err(GSMError::duplicate(state, event.into())),
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }

    pub(crate) fn process_bridge_proof_timeout(
        &mut self,
        event: BridgeProofTimeoutConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state.clone() {
            GraphState::Contested {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                fulfillment_block_height: _,
                contest_block_height,
            } => {
                if event.bridge_proof_timeout_block_height < last_block_height {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "event has old block height",
                    ));
                }
                if event.bridge_proof_timeout_txid != graph_summary.bridge_proof_timeout {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "invalid bridge proof txid",
                    ));
                }

                self.state = GraphState::BridgeProofTimedout {
                    last_block_height: event.bridge_proof_timeout_block_height,
                    graph_data,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    expected_slash_txid: graph_summary.slash,
                    claim_txid: graph_summary.claim,
                    graph_summary,
                };

                Ok(GSMOutput::default())
            }
            state @ GraphState::BridgeProofTimedout { .. } => {
                Err(GSMError::duplicate(state, event.into()))
            }
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }

    /// Processes the event where a counterproof ACK transaction has been confirmed on-chain.
    ///
    /// Only valid from the `CounterProofPosted` state, transitioning to `Acked`.
    pub(crate) fn process_counterproof_ack(
        &mut self,
        event: CounterProofAckConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        self.check_operator_idx(event.counterprover_idx, &event)?;

        match self.state.clone() {
            GraphState::CounterProofPosted {
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                ..
            } => {
                let graph_owner_idx = self.context().operator_idx();

                let watchtower_slot =
                    watchtower_slot_for_operator(graph_owner_idx, event.counterprover_idx)
                        .ok_or_else(|| {
                            GSMError::rejected(
                                self.state.clone(),
                                event.clone().into(),
                                format!(
                                    "operator index {} has no watchtower slot in this graph",
                                    event.counterprover_idx
                                ),
                            )
                        })?;

                let expected_ack_txid = graph_summary
                    .counterproofs
                    .get(watchtower_slot)
                    .map(|summary| summary.counterproof_ack)
                    .ok_or_else(|| {
                        GSMError::rejected(
                            self.state.clone(),
                            event.clone().into(),
                            format!(
                                "missing counterproof ACK mapping for operator index {}",
                                event.counterprover_idx
                            ),
                        )
                    })?;

                if event.counterproof_ack_txid != expected_ack_txid {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "Invalid counterproof ACK transaction",
                    ));
                }

                self.state = GraphState::Acked {
                    last_block_height: event.counterproof_ack_block_height,
                    graph_data,
                    signatures,
                    contest_block_height,
                    expected_slash_txid: graph_summary.slash,
                    claim_txid: graph_summary.claim,
                    fulfillment_txid,
                };

                Ok(GSMOutput::new())
            }
            state @ GraphState::Acked { .. } => Err(GSMError::duplicate(state, event.into())),
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }
}
