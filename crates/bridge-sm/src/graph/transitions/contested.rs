use std::sync::Arc;

use strata_bridge_tx_graph::game_graph::GameConnectors;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::{BridgeProofConfirmedEvent, BridgeProofTimeoutConfirmedEvent, ContestConfirmedEvent},
    machine::{GSMOutput, GraphSM, generate_game_graph},
    state::GraphState,
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

    /// Processes the event where a bridge proof transaction has been confirmed on-chain.
    ///
    /// Only valid from the `Contested` state, transitions to `BridgeProofPosted`.
    /// If the current operator is a watchtower, verifies the bridge proof using the
    /// configured predicate and emits a [`GraphDuty::PublishCounterProof`] duty if
    /// verification fails.
    pub(crate) fn process_bridge_proof(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        event: BridgeProofConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state.clone() {
            GraphState::Contested {
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                ..
            } => {
                let bridge_proof = event.proof.clone();

                let is_watchtower =
                    self.context().operator_idx() != self.context().operator_table().pov_idx();
                let is_proof_invalid = cfg.bridge_proof_predicate.verify(&bridge_proof);

                let mut duties = Vec::new();

                // Watchtower challenges an invalid bridge proof by publishing a counterproof
                if is_watchtower && !is_proof_invalid {
                    let game_graph = generate_game_graph(&cfg, self.context(), graph_data);
                    let watchtower_idx = self.context().watchtower_index();

                    let counterproof_graph = game_graph
                        .counterproofs
                        .get(watchtower_idx as usize)
                        .ok_or_else(|| {
                            GSMError::rejected(
                                self.state.clone(),
                                event.clone().into(),
                                format!(
                                    "missing counterproof graph for watchtower {watchtower_idx}"
                                ),
                            )
                        })?;

                    duties.push(GraphDuty::PublishCounterProof {
                        graph_idx: self.context().graph_idx(),
                        counterproof_tx: counterproof_graph.counterproof.as_ref().clone(),
                        proof: bridge_proof.clone(),
                    });
                }

                self.state = GraphState::BridgeProofPosted {
                    last_block_height: event.bridge_proof_block_height,
                    graph_data,
                    graph_summary: graph_summary.clone(),
                    signatures: signatures.clone(),
                    fulfillment_txid,
                    contest_block_height,
                    bridge_proof_txid: event.bridge_proof_txid,
                    bridge_proof_block_height: event.bridge_proof_block_height,
                    proof: bridge_proof,
                };

                Ok(GSMOutput::with_duties(duties))
            }
            state @ GraphState::BridgeProofPosted { .. } => {
                Err(GSMError::duplicate(state, event.into()))
            }
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
}
