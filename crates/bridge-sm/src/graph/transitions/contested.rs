use std::sync::Arc;

use bitcoin::{Transaction, Txid, hashes::Hash};
use strata_bridge_primitives::{proof::verify_bridge_proof, types::OperatorIdx};
use strata_bridge_tx_graph::{
    game_graph::{GameConnectors, GameGraphSummary},
    musig_functor::GameFunctor,
};

use crate::{
    graph::{
        config::GraphSMCfg,
        duties::GraphDuty,
        errors::{GSMError, GSMResult},
        events::{
            BridgeProofConfirmedEvent, BridgeProofTimeoutConfirmedEvent, ContestConfirmedEvent,
            CounterProofAckConfirmedEvent, CounterProofNackConfirmedEvent, StakeSpentEvent,
        },
        machine::{GSMOutput, GraphSM, generate_game_graph},
        state::{AbortReason, GraphState},
        watchtower::watchtower_slot_for_operator,
    },
    tx_classifier::{
        spends_contest_proof_connector, spends_counterproof_ack_nack, spends_stake_outpoint,
    },
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
                stake_spent,
                payout_connector_spent,
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
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    signatures,
                    fulfillment_txid,
                    fulfillment_block_height,
                    contest_block_height: event.contest_block_height,
                    stake_spent,
                    payout_connector_spent,
                };

                // The graph owner must publish a bridge proof to defend against the contest
                let duties =
                    if self.context().operator_idx() == self.context().operator_table().pov_idx() {
                        let setup_params = self.context().generate_setup_params(&cfg, &graph_data);
                        let connectors = GameConnectors::new(
                            graph_data.game_index,
                            &cfg.game_graph_params,
                            &setup_params,
                        );

                        vec![GraphDuty::GenerateAndPublishBridgeProof {
                            graph_idx: self.context().graph_idx(),
                            last_block_height,
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
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                if !validate_bridge_proof_spend(&graph_summary, &event) {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "bridge proof tx does not spend the contest proof connector \
                         or matches bridge proof timeout txid",
                    ));
                }

                let bridge_proof = event.proof.clone();

                let is_watchtower =
                    self.context().operator_idx() != self.context().operator_table().pov_idx();
                let is_proof_valid =
                    verify_bridge_proof(&cfg.bridge_proof_predicate, &bridge_proof);

                let mut duties = Vec::new();

                // Watchtower challenges an invalid bridge proof by publishing a counterproof
                if is_watchtower && !is_proof_valid {
                    let game_graph = generate_game_graph(&cfg, self.context(), &graph_data);
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

                    let n_of_n_signature = GameFunctor::unpack(
                        signatures.clone(),
                        self.context().watchtower_pubkeys().len(),
                    )
                    .expect("Failed to unpack graph signatures for counterproof N/N signature")
                    .watchtowers[watchtower_idx]
                        .counterproof[0];

                    duties.push(GraphDuty::GenerateAndPublishCounterProof {
                        graph_idx: self.context().graph_idx(),
                        game_index: graph_data.game_index,
                        counterproof_tx: counterproof_graph.counterproof.clone(),
                        n_of_n_signature,
                        proof: bridge_proof.clone(),
                        bridge_proof_tx: event.tx.clone(),
                        operator_table: self.context().operator_table().clone(),
                    });
                }

                self.state = GraphState::BridgeProofPosted {
                    last_block_height: event.bridge_proof_block_height,
                    graph_data,
                    graph_summary: graph_summary.clone(),
                    signatures: signatures.clone(),
                    fulfillment_txid,
                    contest_block_height,
                    bridge_proof_tx: event.tx.clone(),
                    bridge_proof_block_height: event.bridge_proof_block_height,
                    proof: bridge_proof,
                    stake_spent,
                    payout_connector_spent,
                };

                Ok(GSMOutput::with_duties(duties))
            }
            GraphState::CounterProofPosted {
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                refuted_bridge_proof,
                counterproofs_and_confs,
                counterproof_nacks,
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                if refuted_bridge_proof.is_some() {
                    return Err(GSMError::duplicate(self.state.clone(), event.into()));
                }

                if !validate_bridge_proof_spend(&graph_summary, &event) {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "bridge proof tx does not spend the contest proof connector \
                         or matches bridge proof timeout txid",
                    ));
                }

                let bridge_proof = event.proof.clone();
                let pov_idx = self.context().operator_table().pov_idx();
                let is_watchtower = self.context().operator_idx() != pov_idx;
                let is_proof_valid =
                    verify_bridge_proof(&cfg.bridge_proof_predicate, &bridge_proof);
                let counterproof_exists = counterproofs_and_confs.contains_key(&pov_idx);

                let mut duties = Vec::new();

                if is_watchtower && !is_proof_valid && !counterproof_exists {
                    let game_graph = generate_game_graph(&cfg, self.context(), &graph_data);
                    let watchtower_idx =
                        watchtower_slot_for_operator(self.context().operator_idx(), pov_idx)
                            .expect("watchtower slot must be present for non-pov operator");

                    let counterproof_graph = game_graph.counterproofs.get(watchtower_idx).expect(
                        "counterproof graph must be present in state for watchtower operator",
                    );

                    let n_of_n_signature = GameFunctor::unpack(
                        signatures.clone(),
                        self.context().watchtower_pubkeys().len(),
                    )
                    .expect("Failed to unpack graph signatures for counterproof N/N signature")
                    .watchtowers[watchtower_idx]
                        .counterproof[0];

                    duties.push(GraphDuty::GenerateAndPublishCounterProof {
                        graph_idx: self.context().graph_idx(),
                        game_index: graph_data.game_index,
                        counterproof_tx: counterproof_graph.counterproof.clone(),
                        n_of_n_signature,
                        proof: bridge_proof.clone(),
                        bridge_proof_tx: event.tx.clone(),
                        operator_table: self.context().operator_table().clone(),
                    });
                }

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.bridge_proof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_bridge_proof: Some((event.tx.clone(), bridge_proof)),
                    counterproofs_and_confs,
                    counterproof_nacks,
                    stake_spent,
                    payout_connector_spent,
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
                last_block_height: _,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                fulfillment_block_height: _,
                contest_block_height,
                stake_spent,
                payout_connector_spent: _,
            } => {
                if event.bridge_proof_timeout_txid != graph_summary.bridge_proof_timeout {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "invalid bridge proof txid",
                    ));
                }

                // The only path forward from `BridgeProofTimedout` is slash. If
                // the stake outpoint is already gone, slash is impossible —
                // abort directly instead of entering a state with no exit.
                if let Some(spending_txid) = stake_spent {
                    self.state = GraphState::Aborted {
                        claim_txid: graph_summary.claim,
                        reason: AbortReason::StakeSpent { spending_txid },
                    };
                    return Ok(GSMOutput::default());
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
                refuted_bridge_proof,
                stake_spent,
                ..
            } if refuted_bridge_proof.is_none() => {
                if event.bridge_proof_timeout_txid != graph_summary.bridge_proof_timeout {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "invalid bridge proof txid",
                    ));
                }

                if let Some(spending_txid) = stake_spent {
                    self.state = GraphState::Aborted {
                        claim_txid: graph_summary.claim,
                        reason: AbortReason::StakeSpent { spending_txid },
                    };
                    return Ok(GSMOutput::default());
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
                refuted_bridge_proof,
                counterproofs_and_confs,
                mut counterproof_nacks,
                stake_spent,
                payout_connector_spent,
            } => {
                // Validate that the NACK tx spends the correct counterproof
                // ACK/NACK output and is not a known counterproof ACK.
                if !validate_counterproof_nack(
                    &graph_summary,
                    self.context().operator_idx(),
                    event.counterprover_idx,
                    &event.tx,
                ) {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "counterproof NACK tx does not spend the expected counterproof outpoint",
                    ));
                }

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
                counterproof_nacks.insert(event.counterprover_idx, event.tx.compute_txid());

                // Transition to AllNackd once every possible counterproof has been nack'd
                // (all watchtower slots), otherwise stay in CounterProofPosted.
                let expected_nacks = graph_summary.counterproofs.len();
                if counterproof_nacks.len() == expected_nacks {
                    // The only path forward from `AllNackd` is the contested
                    // payout, which consumes the payout connector. If the
                    // connector is already gone, payout is impossible — abort
                    // directly instead of entering a state with no exit.
                    if let Some(spending_txid) = payout_connector_spent {
                        self.state = GraphState::Aborted {
                            claim_txid: graph_summary.claim,
                            reason: AbortReason::PayoutConnectorSpent { spending_txid },
                        };
                        return Ok(GSMOutput::new());
                    }

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
                        refuted_bridge_proof,
                        counterproofs_and_confs,
                        counterproof_nacks,
                        stake_spent,
                        payout_connector_spent,
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
                stake_spent,
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

                // The only path forward from `Acked` is slash. If the stake
                // outpoint is already gone, slash is impossible — abort
                // directly instead of entering a state with no exit.
                if let Some(spending_txid) = stake_spent {
                    self.state = GraphState::Aborted {
                        claim_txid: graph_summary.claim,
                        reason: AbortReason::StakeSpent { spending_txid },
                    };
                    return Ok(GSMOutput::new());
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

    /// Processes the event where the operator's stake outpoint has been
    /// consumed on-chain.
    pub(crate) fn process_stake_spent(&mut self, event: StakeSpentEvent) -> GSMResult<GSMOutput> {
        // Defensive guard: the classifier emits this event only for txs that
        // consume the stake outpoint. Verify the invariant here as well so
        // misrouted or directly-injected events cannot record `stake_spent`
        // or terminalize the graph.
        if !spends_stake_outpoint(&self.context().stake_outpoint(), &event.tx) {
            return Err(GSMError::rejected(
                self.state.clone(),
                event.into(),
                "stake spent event tx does not spend the stake outpoint",
            ));
        }

        let spend_txid = event.tx.compute_txid();

        // A stake spend is already recorded: matching txid is a duplicate
        // re-delivery; any other txid is rejected.
        if let Some(recorded) = self.state.stake_spent_txid() {
            if recorded == spend_txid {
                return Err(GSMError::duplicate(self.state.clone(), event.into()));
            }
            return Err(GSMError::rejected(
                self.state.clone(),
                event.into(),
                "stake already recorded with a different spending txid",
            ));
        }

        // If the stake is spent by this graph's slash transaction, we can
        // directly transition to `Slashed` without going through the
        // intermediate states. This is only possible from certain states but
        // for simplicity, we transition directly and depend on bitcoin
        // consensus to make sure the transaction graph is being followed.
        //
        // No cross-SM signal is emitted on this transition. Operator-set
        // membership is tracked by the `StakeSM` via its
        // `active_operator_snapshot`, which is driven directly by on-chain
        // slash and unstake observations.
        if self.state.expected_slash_txid() == Some(spend_txid) {
            self.state = GraphState::Slashed {
                // use a sentinel value if no claim exists.
                // NOTE: (@Rajil1213) in practice, this should never happen
                // but since this information is extracted from the state whose impl is not
                // exhaustively checked here, we need to handle the possibility of missing claim
                // txid.
                claim_txid: self.state.claim_txid().unwrap_or(Txid::all_zeros()),
                slash_txid: spend_txid,
            };
            return Ok(GSMOutput::new());
        }

        // Stake spent by a transaction other than this graph's slash.

        // The only possible path from here was slash, so if the stake has
        // already been spent, abort.
        if matches!(
            self.state,
            GraphState::BridgeProofTimedout { .. } | GraphState::Acked { .. }
        ) {
            self.state = GraphState::Aborted {
                claim_txid: self.state.claim_txid().unwrap_or(Txid::all_zeros()),
                reason: AbortReason::StakeSpent {
                    spending_txid: spend_txid,
                },
            };
            return Ok(GSMOutput::new());
        }

        // Post-`Claimed` two-fact state with the connector already gone:
        // can't get payout and can't get slashed now, only thing to do is
        // abort.
        if let Some(payout_connector_spending_txid) = self.state.payout_connector_spent_txid() {
            self.state = GraphState::Aborted {
                claim_txid: self.state.claim_txid().unwrap_or(Txid::all_zeros()),
                reason: AbortReason::Both {
                    stake_spending_txid: spend_txid,
                    payout_connector_spending_txid,
                },
            };
            return Ok(GSMOutput::new());
        }

        // States that carry `stake_spent` but have not yet seen the connector
        // spent: record the spend and stay. The GSM will react to subsequent
        // events that might still complete the game.
        if self.state.set_stake_spent(spend_txid) {
            return Ok(GSMOutput::new());
        }

        // States without a `stake_spent` field. The spend is allowed in the
        // protocol but the GSM has no field to record it on:
        // - pre-`NoncesCollected` (Created / GraphGenerated / AdaptorsVerified): no need to record,
        //   the graph hasn't progressed far enough.
        // - `AllNackd`: contested payout does not depend on the stake outpoint, so the spend is
        //   irrelevant.
        // - `Withdrawn` / `Slashed` / `Aborted`: terminal, reject all events.
        Err(GSMError::rejected(
            self.state.clone(),
            event.into(),
            "stake spend has no actionable interpretation in this state",
        ))
    }
}

/// Validates that the bridge proof tx spends the contest proof connector
/// and is not the bridge proof timeout transaction.
fn validate_bridge_proof_spend(
    summary: &GameGraphSummary,
    event: &BridgeProofConfirmedEvent,
) -> bool {
    event.tx.compute_txid() != summary.bridge_proof_timeout
        && spends_contest_proof_connector(summary.contest, &event.tx)
}

/// Validates that `tx` spends the NACK output of the counterproof transaction.
fn validate_counterproof_nack(
    summary: &GameGraphSummary,
    graph_owner_idx: OperatorIdx,
    counterprover_idx: OperatorIdx,
    tx: &Transaction,
) -> bool {
    watchtower_slot_for_operator(graph_owner_idx, counterprover_idx)
        .and_then(|slot| summary.counterproofs.get(slot))
        .is_some_and(|cp| {
            tx.compute_txid() != cp.counterproof_ack
                && spends_counterproof_ack_nack(cp.counterproof, tx)
        })
}
