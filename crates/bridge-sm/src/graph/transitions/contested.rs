use std::{collections::BTreeMap, sync::Arc};

use musig2::AggNonce;
use strata_bridge_primitives::types::OperatorIdx;

use crate::{
    graph::{
        config::GraphSMCfg,
        duties::GraphDuty,
        errors::{GSMError, GSMResult},
        events::{
            AdaptorsVerifiedEvent, BridgeProofConfirmedEvent, BridgeProofTimeoutConfirmedEvent,
            ClaimConfirmedEvent, ContestConfirmedEvent, CounterProofAckConfirmedEvent,
            CounterProofConfirmedEvent, CounterProofNackConfirmedEvent, FulfillmentConfirmedEvent,
            GraphDataGeneratedEvent, GraphNonceReceivedEvent, GraphPartialReceivedEvent,
            PayoutConfirmedEvent, PayoutConnectorSpentEvent, SlashConfirmedEvent,
            WithdrawalAssignedEvent,
        },
        machine::{DepositSM, GSMOutput},
        state::{AbortReason, GraphState},
    },
    signals::{GraphSignal, GraphToDeposit, GraphToOperator},
};

impl DepositSM {
    /// Processes the event where graph data has been produced for this graph instance.
    ///
    /// Transitions from [`GraphState::Created`] to [`GraphState::GraphGenerated`].
    /// Emits a [`GraphDuty::VerifyAdaptors`] duty.
    pub(crate) fn process_graph_data(
        &mut self,
        graph_data: GraphDataGeneratedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Created {
                last_block_height, ..
            } => {
                let last_block_height = *last_block_height;

                let graph_summary = graph_data.graph_data.summarize();

                self.state = GraphState::GraphGenerated {
                    last_block_height,
                    graph_data: graph_data.graph_data,
                    graph_summary,
                };

                Ok(GSMOutput::with_duties(vec![GraphDuty::VerifyAdaptors]))
            }
            GraphState::GraphGenerated { .. } => {
                Err(GSMError::duplicate(self.state().clone(), graph_data.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                graph_data.into(),
                None,
            )),
        }
    }

    /// Processes the event where all adaptors for the graph have been verified.
    ///
    /// Transitions from [`GraphState::GraphGenerated`] to [`GraphState::AdaptorsVerified`].
    /// Emits a [`GraphDuty::PublishGraphNonces`] duty.
    pub(crate) fn process_adaptors_verification(
        &mut self,
        adaptors: AdaptorsVerifiedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::GraphGenerated {
                last_block_height,
                graph_data,
                graph_summary,
            } => {
                self.state = GraphState::AdaptorsVerified {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    pubnonces: BTreeMap::new(),
                };

                Ok(GSMOutput::with_duties(vec![
                    GraphDuty::PublishGraphNonces {
                        deposit_idx: self.context.deposit_idx,
                        operator_idx: self.context.operator_idx,
                    },
                ]))
            }
            GraphState::AdaptorsVerified { .. } => {
                Err(GSMError::duplicate(self.state().clone(), adaptors.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                adaptors.into(),
                None,
            )),
        }
    }

    /// Processes the event where a nonce bundle is received from an operator.
    ///
    /// Collects nonces from each operator. When all operators have provided nonces,
    /// transitions from [`GraphState::AdaptorsVerified`] to [`GraphState::NoncesCollected`]
    /// and emits a [`GraphDuty::PublishGraphPartials`] duty.
    pub(crate) fn process_nonces(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        nonce_event: GraphNonceReceivedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state_mut() {
            GraphState::AdaptorsVerified {
                last_block_height,
                graph_data,
                graph_summary,
                pubnonces,
            } => {
                // Check for duplicate nonce from this operator
                if pubnonces.contains_key(&nonce_event.operator_idx) {
                    return Err(GSMError::duplicate(
                        self.state().clone(),
                        nonce_event.into(),
                    ));
                }

                pubnonces.insert(nonce_event.operator_idx, nonce_event.nonce);

                if pubnonces.len() == cfg.num_operators {
                    let agg_nonce = AggNonce::sum(pubnonces.values().cloned());
                    let claim_txid = graph_summary.claim;

                    self.state = GraphState::NoncesCollected {
                        last_block_height: *last_block_height,
                        agg_nonce: agg_nonce.clone(),
                        pubnonces: pubnonces.clone(),
                        partial_signatures: BTreeMap::new(),
                        graph_data: graph_data.clone(),
                        graph_summary: graph_summary.clone(),
                    };

                    Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishGraphPartials {
                            deposit_idx: self.context.deposit_idx,
                            operator_idx: self.context.operator_idx,
                            agg_nonce,
                            claim_txid,
                        },
                    ]))
                } else {
                    Ok(GSMOutput::new())
                }
            }
            GraphState::NoncesCollected { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                nonce_event.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                nonce_event.into(),
                None,
            )),
        }
    }

    /// Processes the event where a partial signature is received from an operator.
    ///
    /// Collects partial signatures from each operator. When all operators have provided partials,
    /// transitions from [`GraphState::NoncesCollected`] to [`GraphState::GraphSigned`]
    /// and emits a [`GraphSignal::ToDeposit`] signal with [`GraphToDeposit::GraphAvailable`].
    pub(crate) fn process_partials(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        partial_event: GraphPartialReceivedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state_mut() {
            GraphState::NoncesCollected {
                last_block_height,
                pubnonces,
                partial_signatures,
                graph_data,
                graph_summary,
                ..
            } => {
                // Check that operator nonces exist
                if !pubnonces.contains_key(&partial_event.operator_idx) {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        partial_event.into(),
                        "Operator nonces not found",
                    ));
                }

                // Check for duplicate partial signature from this operator
                if partial_signatures.contains_key(&partial_event.operator_idx) {
                    return Err(GSMError::duplicate(
                        self.state().clone(),
                        partial_event.into(),
                    ));
                }

                // TODO: verify partial signature

                partial_signatures.insert(partial_event.operator_idx, partial_event.partial_sig);

                if partial_signatures.len() == cfg.num_operators {
                    // TODO: aggregate partial signatures into final signature
                    let signature = todo!("aggregate graph partial signatures");

                    self.state = GraphState::GraphSigned {
                        last_block_height: *last_block_height,
                        graph_data: graph_data.clone(),
                        graph_summary: graph_summary.clone(),
                        signature,
                    };

                    Ok(GSMOutput::with_signals(vec![GraphSignal::ToDeposit(
                        GraphToDeposit::GraphAvailable {
                            operator_idx: self.context.operator_idx,
                        },
                    )]))
                } else {
                    Ok(GSMOutput::new())
                }
            }
            GraphState::GraphSigned { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                partial_event.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                partial_event.into(),
                None,
            )),
        }
    }

    /// Processes the event where a withdrawal has been assigned for this graph.
    ///
    /// Transitions from [`GraphState::GraphSigned`] to [`GraphState::Assigned`].
    /// Emits no duties or signals.
    pub(crate) fn process_assignment(
        &mut self,
        assignment: WithdrawalAssignedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::GraphSigned {
                last_block_height,
                graph_data,
                graph_summary,
                signature,
            } => {
                self.state = GraphState::Assigned {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    signature: *signature,
                    assignee: assignment.assignee,
                    deadline: assignment.deadline,
                    recipient_desc: assignment.recipient_desc,
                };

                Ok(GSMOutput::new())
            }
            GraphState::Assigned { .. } => {
                Err(GSMError::duplicate(self.state().clone(), assignment.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                assignment.into(),
                None,
            )),
        }
    }

    /// Processes the event where a fulfillment transaction has been confirmed on-chain.
    ///
    /// Transitions from [`GraphState::Assigned`] to [`GraphState::Fulfilled`].
    /// Emits a [`GraphDuty::PublishClaim`] duty.
    pub(crate) fn process_fulfillment(
        &mut self,
        fulfillment: FulfillmentConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Assigned {
                last_block_height,
                graph_data,
                graph_summary,
                ..
            } => {
                let claim_txid = graph_summary.claim;

                self.state = GraphState::Fulfilled {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    fulfillment_txid: fulfillment.fulfillment_txid,
                    fulfillment_block_height: fulfillment.fulfillment_block_height,
                };

                Ok(GSMOutput::with_duties(vec![GraphDuty::PublishClaim {
                    claim_txid,
                }]))
            }
            GraphState::Fulfilled { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                fulfillment.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                fulfillment.into(),
                None,
            )),
        }
    }

    /// Re-emits the [`GraphDuty::PublishClaim`] duty while staying in [`GraphState::Fulfilled`].
    ///
    /// Publishing of claim is idempotent so it is fine to create duties multiple times
    /// in this state.
    pub(crate) fn process_activation(&self) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Fulfilled { graph_summary, .. } => {
                let claim_txid = graph_summary.claim;

                Ok(GSMOutput::with_duties(vec![GraphDuty::PublishClaim {
                    claim_txid,
                }]))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                todo!("activation event"),
                None,
            )),
        }
    }

    /// Processes the event where a claim transaction has been confirmed on-chain.
    ///
    /// **Valid case**: From [`GraphState::Fulfilled`] → [`GraphState::Claimed`] with empty output.
    ///
    /// **Faulty cases** (claim without fulfillment): From [`GraphState::Assigned`],
    /// [`GraphState::GraphSigned`], or [`GraphState::NoncesCollected`] →
    /// [`GraphState::Claimed`] with a [`GraphDuty::PublishContest`] duty.
    ///
    /// In all cases, validates that the claim txid matches `graph_summary.claim`.
    pub(crate) fn process_claim(&mut self, claim: ClaimConfirmedEvent) -> GSMResult<GSMOutput> {
        match self.state() {
            // Valid case: claim after fulfillment
            GraphState::Fulfilled {
                last_block_height,
                graph_data,
                graph_summary,
                fulfillment_txid,
                fulfillment_block_height,
            } => {
                if claim.claim_txid != graph_summary.claim {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        claim.into(),
                        "Invalid claim transaction",
                    ));
                }

                self.state = GraphState::Claimed {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    fulfillment_txid: Some(*fulfillment_txid),
                    fulfillment_block_height: Some(*fulfillment_block_height),
                    claim_block_height: claim.claim_block_height,
                };

                Ok(GSMOutput::new())
            }
            // Faulty cases: claim without fulfillment
            GraphState::Assigned {
                last_block_height,
                graph_data,
                graph_summary,
                ..
            }
            | GraphState::GraphSigned {
                last_block_height,
                graph_data,
                graph_summary,
                ..
            }
            | GraphState::NoncesCollected {
                last_block_height,
                graph_data,
                graph_summary,
                ..
            } => {
                if claim.claim_txid != graph_summary.claim {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        claim.into(),
                        "Invalid claim transaction",
                    ));
                }

                let claim_txid = graph_summary.claim;

                self.state = GraphState::Claimed {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    fulfillment_txid: None,
                    fulfillment_block_height: None,
                    claim_block_height: claim.claim_block_height,
                };

                Ok(GSMOutput::with_duties(vec![GraphDuty::PublishContest {
                    claim_txid,
                }]))
            }
            GraphState::Claimed { .. } => {
                Err(GSMError::duplicate(self.state().clone(), claim.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                claim.into(),
                None,
            )),
        }
    }

    /// Processes the event where a contest transaction has been confirmed on-chain.
    ///
    /// Transitions from [`GraphState::Claimed`] to [`GraphState::Contested`].
    /// Emits a [`GraphDuty::PublishBridgeProof`] duty.
    ///
    /// Validates that the contest txid matches `graph_summary.contest`.
    pub(crate) fn process_contest(
        &mut self,
        contest: ContestConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Claimed {
                last_block_height,
                graph_data,
                graph_summary,
                fulfillment_txid,
                fulfillment_block_height,
                ..
            } => {
                if contest.contest_txid != graph_summary.contest {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        contest.into(),
                        "Invalid contest transaction",
                    ));
                }

                self.state = GraphState::Contested {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    fulfillment_txid: *fulfillment_txid,
                    fulfillment_block_height: *fulfillment_block_height,
                    contest_block_height: contest.contest_block_height,
                };

                Ok(GSMOutput::with_duties(vec![
                    GraphDuty::PublishBridgeProof {
                        deposit_idx: self.context.deposit_idx,
                        operator_idx: self.context.operator_idx,
                    },
                ]))
            }
            GraphState::Contested { .. } => {
                Err(GSMError::duplicate(self.state().clone(), contest.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                contest.into(),
                None,
            )),
        }
    }

    /// Processes the event where a bridge proof transaction has been confirmed on-chain.
    ///
    /// Transitions from [`GraphState::Contested`] to [`GraphState::BridgeProofPosted`].
    /// Emits a [`GraphDuty::PublishCounterProof`] duty.
    pub(crate) fn process_bridge_proof(
        &mut self,
        bridge_proof: BridgeProofConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Contested {
                last_block_height,
                graph_data,
                graph_summary,
                fulfillment_txid,
                fulfillment_block_height,
                contest_block_height,
            } => {
                let proof = bridge_proof.proof.clone();

                self.state = GraphState::BridgeProofPosted {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    fulfillment_txid: *fulfillment_txid,
                    fulfillment_block_height: *fulfillment_block_height,
                    contest_block_height: *contest_block_height,
                    bridge_proof_txid: bridge_proof.bridge_proof_txid,
                    bridge_proof_block_height: bridge_proof.bridge_proof_block_height,
                    proof: bridge_proof.proof,
                };

                Ok(GSMOutput::with_duties(vec![
                    GraphDuty::PublishCounterProof {
                        deposit_idx: self.context.deposit_idx,
                        operator_idx: self.context.operator_idx,
                        proof,
                    },
                ]))
            }
            GraphState::BridgeProofPosted { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                bridge_proof.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                bridge_proof.into(),
                None,
            )),
        }
    }

    /// Processes the event where a bridge proof timeout transaction has been confirmed on-chain.
    ///
    /// Transitions from [`GraphState::Contested`] to [`GraphState::BridgeProofTimedout`].
    /// Emits no duties or signals.
    ///
    /// Validates that the timeout txid matches `graph_summary.bridge_proof_timeout`.
    pub(crate) fn process_bridge_proof_timeout(
        &mut self,
        timeout: BridgeProofTimeoutConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Contested {
                last_block_height,
                graph_data,
                graph_summary,
                fulfillment_txid,
                fulfillment_block_height,
                contest_block_height,
            } => {
                if timeout.bridge_proof_timeout_txid != graph_summary.bridge_proof_timeout {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        timeout.into(),
                        "Invalid bridge proof timeout transaction",
                    ));
                }

                self.state = GraphState::BridgeProofTimedout {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    fulfillment_txid: *fulfillment_txid,
                    fulfillment_block_height: *fulfillment_block_height,
                    contest_block_height: *contest_block_height,
                    expected_slash_txid: graph_summary.slash,
                    claim_txid: graph_summary.claim,
                };

                Ok(GSMOutput::new())
            }
            GraphState::BridgeProofTimedout { .. } => {
                Err(GSMError::duplicate(self.state().clone(), timeout.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                timeout.into(),
                None,
            )),
        }
    }

    /// Processes the event where a counterproof transaction has been confirmed on-chain.
    ///
    /// **From [`GraphState::BridgeProofPosted`]**: Transitions to
    /// [`GraphState::CounterProofPosted`] with the first counterproof recorded. Emits a
    /// [`GraphDuty::PublishCounterProofNack`] duty.
    ///
    /// **From [`GraphState::CounterProofPosted`]**: Accumulates additional counterproofs in-place.
    /// If the counterproof is from a new operator, records it and emits a
    /// [`GraphDuty::PublishCounterProofNack`] duty. Duplicate counterproofs from the same operator
    /// are ignored.
    ///
    /// Validates that the counterproof txid matches one of `graph_summary.counterproofs`.
    pub(crate) fn process_counterproof(
        &mut self,
        counterproof: CounterProofConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state_mut() {
            GraphState::BridgeProofPosted {
                last_block_height,
                graph_data,
                graph_summary,
                contest_block_height,
                ..
            } => {
                let counter_prover_idx = graph_summary
                    .counterproofs
                    .iter()
                    .position(|cp| cp.counterproof == counterproof.counterproof_txid)
                    .ok_or_else(|| {
                        GSMError::rejected(
                            self.state().clone(),
                            counterproof.clone().into(),
                            "Invalid counterproof transaction",
                        )
                    })? as OperatorIdx;

                self.state = GraphState::CounterProofPosted {
                    last_block_height: *last_block_height,
                    graph_data: graph_data.clone(),
                    graph_summary: graph_summary.clone(),
                    contest_block_height: *contest_block_height,
                    counterproofs_and_confs: BTreeMap::from([(
                        counter_prover_idx,
                        (
                            counterproof.counterproof_txid,
                            counterproof.counterproof_block_height,
                        ),
                    )]),
                    counterproof_nacks: BTreeMap::new(),
                };

                Ok(GSMOutput::with_duties(vec![
                    GraphDuty::PublishCounterProofNack {
                        deposit_idx: self.context.deposit_idx,
                        counter_prover_idx,
                    },
                ]))
            }
            GraphState::CounterProofPosted {
                graph_summary,
                counterproofs_and_confs,
                ..
            } => {
                let counter_prover_idx = graph_summary
                    .counterproofs
                    .iter()
                    .position(|cp| cp.counterproof == counterproof.counterproof_txid)
                    .ok_or_else(|| {
                        GSMError::rejected(
                            self.state().clone(),
                            counterproof.clone().into(),
                            "Invalid counterproof transaction",
                        )
                    })? as OperatorIdx;

                // Ignore duplicate counterproofs from the same operator
                if counterproofs_and_confs.contains_key(&counter_prover_idx) {
                    return Ok(GSMOutput::new());
                }

                counterproofs_and_confs.insert(
                    counter_prover_idx,
                    (
                        counterproof.counterproof_txid,
                        counterproof.counterproof_block_height,
                    ),
                );

                Ok(GSMOutput::with_duties(vec![
                    GraphDuty::PublishCounterProofNack {
                        deposit_idx: self.context.deposit_idx,
                        counter_prover_idx,
                    },
                ]))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                counterproof.into(),
                None,
            )),
        }
    }

    /// Processes the event where a counterproof ACK transaction has been confirmed on-chain.
    ///
    /// Transitions from [`GraphState::CounterProofPosted`] to [`GraphState::Acked`].
    /// Emits no duties or signals.
    ///
    /// Validates that the ACK txid matches one of the counterproof ACK txids in
    /// `graph_summary.counterproofs`.
    pub(crate) fn process_counterproof_ack(
        &mut self,
        ack: CounterProofAckConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::CounterProofPosted {
                last_block_height,
                graph_summary,
                contest_block_height,
                ..
            } => {
                if !graph_summary
                    .counterproofs
                    .iter()
                    .any(|cp| cp.counterproof_ack == ack.counterproof_ack_txid)
                {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        ack.into(),
                        "Invalid counterproof ACK transaction",
                    ));
                }

                self.state = GraphState::Acked {
                    last_block_height: *last_block_height,
                    contest_block_height: *contest_block_height,
                    expected_slash_txid: graph_summary.slash,
                    claim_txid: graph_summary.claim,
                };

                Ok(GSMOutput::new())
            }
            GraphState::Acked { .. } => Err(GSMError::duplicate(self.state().clone(), ack.into())),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                ack.into(),
                None,
            )),
        }
    }

    /// Processes the event where a counterproof NACK transaction has been confirmed on-chain.
    ///
    /// Accumulates NACKs in [`GraphState::CounterProofPosted`] in-place. When all counterproofs
    /// have been NACK'd (i.e., `counterproof_nacks.len() == graph_summary.counterproofs.len()`),
    /// transitions to [`GraphState::AllNackd`].
    ///
    /// Validates that the `nacker_idx` is a valid counterproof index in `graph_summary`.
    pub(crate) fn process_counterproof_nack(
        &mut self,
        nack: CounterProofNackConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state_mut() {
            GraphState::CounterProofPosted {
                last_block_height,
                graph_data,
                graph_summary,
                contest_block_height,
                counterproof_nacks,
                ..
            } => {
                if nack.nacker_idx as usize >= graph_summary.counterproofs.len() {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        nack.into(),
                        "Invalid counterproof NACK transaction",
                    ));
                }

                counterproof_nacks.insert(nack.nacker_idx, nack.counterproof_nack_txid);

                if counterproof_nacks.len() == graph_summary.counterproofs.len() {
                    self.state = GraphState::AllNackd {
                        last_block_height: *last_block_height,
                        contest_block_height: *contest_block_height,
                        expected_payout_txid: graph_data.contested_payout.as_ref().compute_txid(),
                        possible_slash_txid: graph_summary.slash,
                    };
                }

                Ok(GSMOutput::new())
            }
            GraphState::AllNackd { .. } => {
                Err(GSMError::duplicate(self.state().clone(), nack.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                nack.into(),
                None,
            )),
        }
    }

    /// Processes the event where a slash transaction has been confirmed on-chain.
    ///
    /// Transitions from [`GraphState::BridgeProofTimedout`], [`GraphState::Acked`], or
    /// [`GraphState::AllNackd`] to [`GraphState::Slashed`].
    /// Emits a [`GraphSignal::ToOperator`] signal with [`GraphToOperator::OperatorSlashed`].
    ///
    /// Validates the slash txid against `expected_slash_txid` (for `BridgeProofTimedout` and
    /// `Acked`) or `possible_slash_txid` (for `AllNackd`).
    pub(crate) fn process_slash(&mut self, slash: SlashConfirmedEvent) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::BridgeProofTimedout {
                expected_slash_txid,
                ..
            } => {
                if slash.slash_txid != *expected_slash_txid {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        slash.into(),
                        "Invalid slash transaction",
                    ));
                }

                self.state = GraphState::Slashed {
                    slash_txid: slash.slash_txid,
                };

                Ok(GSMOutput::with_signals(vec![GraphSignal::ToOperator(
                    GraphToOperator::OperatorSlashed {
                        operator_idx: self.context.operator_idx,
                    },
                )]))
            }
            GraphState::Acked {
                expected_slash_txid,
                ..
            } => {
                if slash.slash_txid != *expected_slash_txid {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        slash.into(),
                        "Invalid slash transaction",
                    ));
                }

                self.state = GraphState::Slashed {
                    slash_txid: slash.slash_txid,
                };

                Ok(GSMOutput::with_signals(vec![GraphSignal::ToOperator(
                    GraphToOperator::OperatorSlashed {
                        operator_idx: self.context.operator_idx,
                    },
                )]))
            }
            GraphState::AllNackd {
                possible_slash_txid,
                ..
            } => {
                if slash.slash_txid != *possible_slash_txid {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        slash.into(),
                        "Invalid slash transaction",
                    ));
                }

                self.state = GraphState::Slashed {
                    slash_txid: slash.slash_txid,
                };

                Ok(GSMOutput::with_signals(vec![GraphSignal::ToOperator(
                    GraphToOperator::OperatorSlashed {
                        operator_idx: self.context.operator_idx,
                    },
                )]))
            }
            GraphState::Slashed { .. } => {
                Err(GSMError::duplicate(self.state().clone(), slash.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                slash.into(),
                None,
            )),
        }
    }

    /// Processes the event where a payout transaction has been confirmed on-chain.
    ///
    /// **From [`GraphState::Claimed`]**: Validates that the payout txid matches the uncontested
    /// payout computed from `graph_data`. Transitions to [`GraphState::Withdrawn`].
    ///
    /// **From [`GraphState::BridgeProofPosted`]**: Validates that the payout txid matches the
    /// uncontested payout computed from `graph_data`. Transitions to [`GraphState::Withdrawn`].
    ///
    /// **From [`GraphState::AllNackd`]**: Validates that the payout txid matches the
    /// `expected_payout_txid`. Transitions to [`GraphState::Withdrawn`].
    ///
    /// Emits no duties or signals in all cases.
    pub(crate) fn process_payout(&mut self, payout: PayoutConfirmedEvent) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Claimed { graph_data, .. }
            | GraphState::BridgeProofPosted { graph_data, .. } => {
                let expected_payout_txid = graph_data.uncontested_payout.as_ref().compute_txid();

                if payout.payout_txid != expected_payout_txid {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        payout.into(),
                        "Invalid payout transaction",
                    ));
                }

                self.state = GraphState::Withdrawn {
                    payout_txid: payout.payout_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::AllNackd {
                expected_payout_txid,
                ..
            } => {
                if payout.payout_txid != *expected_payout_txid {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        payout.into(),
                        "Invalid payout transaction",
                    ));
                }

                self.state = GraphState::Withdrawn {
                    payout_txid: payout.payout_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::Withdrawn { .. } => {
                Err(GSMError::duplicate(self.state().clone(), payout.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                payout.into(),
                None,
            )),
        }
    }

    /// Processes the event where the payout connector has been spent by some transaction.
    ///
    /// This is an abort condition. Transitions from any state to [`GraphState::Aborted`].
    /// Emits no duties or signals.
    ///
    /// Note: this should be checked _after_ payout checks, since payouts also spend the connector.
    pub(crate) fn process_payout_connector_spent(
        &mut self,
        connector_spent: PayoutConnectorSpentEvent,
    ) -> GSMResult<GSMOutput> {
        self.state = GraphState::Aborted {
            reason: AbortReason::PayoutConnectorSpent {
                spending_txid: connector_spent.spending_txid,
            },
        };

        Ok(GSMOutput::new())
    }
}
