use std::sync::Arc;

use strata_bridge_primitives::proof::verify_bridge_proof;
use strata_bridge_tx_graph::game_graph::GameConnectors;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::{
        BridgeProofConfirmedEvent, BridgeProofTimeoutConfirmedEvent, ContestConfirmedEvent,
        CounterProofAckConfirmedEvent, CounterProofNackConfirmedEvent, SlashConfirmedEvent,
    },
    machine::{GSMOutput, GraphSM, generate_game_graph},
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
                let is_proof_valid =
                    verify_bridge_proof(&cfg.bridge_proof_predicate, &bridge_proof);

                let mut duties = Vec::new();

                // Watchtower challenges an invalid bridge proof by publishing a counterproof
                if is_watchtower && !is_proof_valid {
                    let game_graph = generate_game_graph(&cfg, self.context(), graph_data);
                    let watchtower_idx = watchtower_slot_for_operator(
                        self.context().operator_idx(),
                        self.context().operator_table().pov_idx(),
                    )
                    .expect("graph owner has no watchtower index");

                    let counterproof_graph = game_graph
                        .counterproofs
                        .get(watchtower_idx)
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
            GraphState::CounterProofPosted {
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                refuted_proof,
                counterproofs_and_confs,
                counterproof_nacks,
                ..
            } => {
                if refuted_proof.is_some() {
                    return Err(GSMError::duplicate(self.state.clone(), event.into()));
                }

                let bridge_proof = event.proof.clone();
                let pov_idx = self.context().operator_table().pov_idx();
                let is_watchtower = self.context().operator_idx() != pov_idx;
                let is_proof_valid =
                    verify_bridge_proof(&cfg.bridge_proof_predicate, &bridge_proof);
                let counterproof_exists = counterproofs_and_confs.contains_key(&pov_idx);

                let mut duties = Vec::new();

                if is_watchtower && !is_proof_valid && !counterproof_exists {
                    let game_graph = generate_game_graph(&cfg, self.context(), graph_data);
                    let watchtower_idx =
                        watchtower_slot_for_operator(self.context().operator_idx(), pov_idx)
                            .expect("watchtower slot must be present for non-pov operator");

                    let counterproof_graph = game_graph.counterproofs.get(watchtower_idx).expect(
                        "counterproof graph must be present in state for watchtower operator",
                    );

                    duties.push(GraphDuty::PublishCounterProof {
                        graph_idx: self.context().graph_idx(),
                        counterproof_tx: counterproof_graph.counterproof.as_ref().clone(),
                        proof: bridge_proof.clone(),
                    });
                }

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.bridge_proof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_proof: Some(bridge_proof),
                    counterproofs_and_confs,
                    counterproof_nacks,
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
            GraphState::CounterProofPosted {
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                refuted_proof,
                ..
            } if refuted_proof.is_none() => {
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

    /// Processes the event where a counterproof NACK transaction has been confirmed on-chain.
    pub(crate) fn process_counterproof_nackd(
        &mut self,
        event: CounterProofNackConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        self.check_operator_idx(event.counterprover_idx, &event)?;

        match self.state.clone() {
            GraphState::CounterProofPosted {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                counterproofs_and_confs,
                mut counterproof_nacks,
            } => {
                // TODO: <https://atlassian.alpenlabs.net/browse/STR-3086>
                // Add validation of the counterproof_nack_txid asserting that it spends
                // the corresponding counterproof transaction.

                // Ensure a counterproof was posted by this operator before accepting a NACK.
                if !counterproofs_and_confs.contains_key(&event.counterprover_idx) {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.clone().into(),
                        format!(
                            "no counterproof posted for operator index {}",
                            event.counterprover_idx
                        ),
                    ));
                }

                // Reject duplicate NACK for the same counterprover.
                if counterproof_nacks.contains_key(&event.counterprover_idx) {
                    return Err(GSMError::duplicate(self.state.clone(), event.into()));
                }
                counterproof_nacks.insert(event.counterprover_idx, event.counterproof_nack_txid);

                // Transition to AllNackd once every possible counterproof has been nack'd
                // (all watchtower slots), otherwise stay in CounterProofPosted.
                let expected_nacks = graph_summary.counterproofs.len();
                if counterproof_nacks.len() == expected_nacks {
                    self.state = GraphState::AllNackd {
                        last_block_height,
                        graph_data,
                        signatures,
                        claim_txid: graph_summary.claim,
                        fulfillment_txid,
                        contest_block_height,
                        expected_payout_txid: graph_summary.contested_payout,
                        possible_slash_txid: graph_summary.slash,
                    };
                } else {
                    self.state = GraphState::CounterProofPosted {
                        last_block_height,
                        graph_data,
                        graph_summary,
                        signatures,
                        fulfillment_txid,
                        contest_block_height,
                        counterproofs_and_confs,
                        counterproof_nacks,
                    };
                }

                Ok(GSMOutput::new())
            }
            state @ GraphState::AllNackd { .. } => Err(GSMError::duplicate(state, event.into())),
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

    pub(crate) fn process_slash(&mut self, event: SlashConfirmedEvent) -> GSMResult<GSMOutput> {
        match self.state.clone() {
            // States with graph_summary that can transition directly to Slashed
            GraphState::Contested { graph_summary, .. }
            | GraphState::BridgeProofPosted { graph_summary, .. }
            | GraphState::CounterProofPosted { graph_summary, .. } => {
                if event.slash_txid != graph_summary.slash {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "Invalid slash transaction",
                    ));
                }

                self.state = GraphState::Slashed {
                    slash_txid: event.slash_txid,
                };

                Ok(GSMOutput::new())
            }
            // States with expected_slash_txid field
            GraphState::BridgeProofTimedout {
                expected_slash_txid,
                ..
            }
            | GraphState::Acked {
                expected_slash_txid,
                ..
            } => {
                if event.slash_txid != expected_slash_txid {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "Invalid slash transaction",
                    ));
                }

                self.state = GraphState::Slashed {
                    slash_txid: event.slash_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::AllNackd {
                possible_slash_txid,
                ..
            } => {
                if event.slash_txid != possible_slash_txid {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "Invalid slash transaction",
                    ));
                }

                self.state = GraphState::Slashed {
                    slash_txid: event.slash_txid,
                };

                Ok(GSMOutput::new())
            }
            state @ GraphState::Slashed { .. } => Err(GSMError::duplicate(state, event.into())),
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }
}
