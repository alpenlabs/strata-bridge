use std::{collections::BTreeMap, sync::Arc};

use musig2::{AggNonce, secp256k1::Message};
use strata_bridge_primitives::scripts::taproot::TaprootTweak;
use strata_bridge_tx_graph2::{game_graph::DepositParams, musig_functor::GameFunctor};

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::{AdaptorsVerifiedEvent, GraphDataGeneratedEvent, GraphNonceReceivedEvent},
    machine::{GSMOutput, GraphSM},
    state::GraphState,
};

impl GraphSM {
    /// Processes the event where graph data has been produced for this graph instance.
    ///
    /// If the PoV operator owns this graph, transitions to
    /// [`GraphState::AdaptorsVerified`] and emits [`GraphDuty::PublishGraphNonces`].
    /// Otherwise, transitions to [`GraphState::GraphGenerated`] and emits
    /// [`GraphDuty::VerifyAdaptors`].
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

                // As the operator who owns this graph, we do not need to verify adaptor
                // signatures. Transition directly to `AdaptorsVerified` state
                let pov_operator_idx = self.context.operator_table().pov_idx();
                if self.context.operator_idx() == pov_operator_idx {
                    let graph_inpoints = game_graph.musig_inpoints().pack();
                    let graph_tweaks = game_graph
                        .musig_signing_info()
                        .pack()
                        .iter()
                        .map(|m| m.tweak)
                        .collect::<Vec<TaprootTweak>>();

                    self.state = GraphState::AdaptorsVerified {
                        last_block_height: *last_block_height,
                        graph_data: deposit_params,
                        graph_summary: game_graph.summarize(),
                        pubnonces: BTreeMap::new(),
                    };

                    let duties = vec![GraphDuty::PublishGraphNonces {
                        graph_idx: self.context.graph_idx(),
                        graph_inpoints,
                        graph_tweaks,
                    }];

                    Ok(GSMOutput::with_duties(duties))
                } else {
                    // The graph owner's counterproof is excluded, so indices
                    // after it are shifted by one. Adjust the pov counterproof index accordingly.
                    let pov_counterproof_idx = if self.context.operator_idx() <= pov_operator_idx {
                        pov_operator_idx - 1
                    } else {
                        pov_operator_idx
                    };

                    let pov_counterproof_graph = game_graph
                        .counterproofs
                        .get(pov_counterproof_idx as usize)
                        .ok_or_else(|| {
                            GSMError::invalid_event(
                                self.state().clone(),
                                graph_data_event.into(),
                                Some(format!(
                                    "Missing counterproof for watchtower {pov_operator_idx}"
                                )),
                            )
                        })?;

                    self.state = GraphState::GraphGenerated {
                        last_block_height: *last_block_height,
                        graph_data: deposit_params,
                        graph_summary: game_graph.summarize(),
                    };

                    let duties = vec![GraphDuty::VerifyAdaptors {
                        graph_idx: self.context.graph_idx(),
                        watchtower_idx: pov_operator_idx,
                        sighashes: pov_counterproof_graph.counterproof.sighashes(),
                    }];

                    Ok(GSMOutput::with_duties(duties))
                }
            }
            GraphState::GraphGenerated { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                graph_data_event.into(),
            )),
            GraphState::AdaptorsVerified { .. }
                if self.context.operator_idx() == self.context.operator_table().pov_idx() =>
            {
                Err(GSMError::duplicate(
                    self.state().clone(),
                    graph_data_event.into(),
                ))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                graph_data_event.into(),
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
        cfg: Arc<GraphSMCfg>,
        adaptors: AdaptorsVerifiedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::GraphGenerated {
                last_block_height,
                graph_data,
                graph_summary,
            } => {
                let game_graph = self.generate_graph(&cfg, *graph_data);
                let graph_inpoints = game_graph.musig_inpoints().pack();
                let graph_tweaks = game_graph
                    .musig_signing_info()
                    .pack()
                    .iter()
                    .map(|m| m.tweak)
                    .collect::<Vec<TaprootTweak>>();

                self.state = GraphState::AdaptorsVerified {
                    last_block_height: *last_block_height,
                    graph_data: *graph_data,
                    graph_summary: graph_summary.clone(),
                    pubnonces: BTreeMap::new(),
                };

                Ok(GSMOutput::with_duties(vec![
                    GraphDuty::PublishGraphNonces {
                        graph_idx: self.context.graph_idx(),
                        graph_inpoints,
                        graph_tweaks,
                    },
                ]))
            }
            GraphState::AdaptorsVerified { .. }
                if self.context.operator_idx() != self.context.operator_table().pov_idx() =>
            {
                Err(GSMError::duplicate(self.state().clone(), adaptors.into()))
            }
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                adaptors.into(),
                None,
            )),
        }
    }

    pub(crate) fn process_nonce_received(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        nonce_received_event: GraphNonceReceivedEvent,
    ) -> GSMResult<GSMOutput> {
        // Validate operator_idx is in the operator table
        self.check_operator_idx(nonce_received_event.operator_idx, &nonce_received_event)?;

        let operator_table_cardinality = self.context().operator_table().cardinality();
        let graph_ctx = self.context().clone();
        let num_nonces = nonce_received_event.nonces.len();

        match self.state_mut() {
            GraphState::AdaptorsVerified {
                last_block_height,
                graph_data,
                graph_summary,
                pubnonces,
            } => {
                // Check for duplicate nonce submission
                if pubnonces.contains_key(&nonce_received_event.operator_idx) {
                    return Err(GSMError::duplicate(
                        self.state().clone(),
                        nonce_received_event.into(),
                    ));
                }

                if GameFunctor::unpack(
                    nonce_received_event.nonces.clone(),
                    operator_table_cardinality,
                )
                .is_none()
                {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        nonce_received_event.into(),
                        "Invalid nonces provided by operator".to_string(),
                    ));
                }

                // Insert the new nonce into the map
                pubnonces.insert(
                    nonce_received_event.operator_idx,
                    nonce_received_event.nonces,
                );

                // Check if we have collected all nonces
                if pubnonces.len() == operator_table_cardinality {
                    // For each nonce position, collect that nonce from every operator
                    // and aggregate them into a single `AggNonce`.
                    let agg_nonces: Vec<_> = (0..num_nonces)
                        .map(|nonce_idx| {
                            let nonces_for_agg: Vec<_> = pubnonces
                                .values()
                                .map(|nonces| nonces[nonce_idx].clone())
                                .collect();
                            AggNonce::sum(nonces_for_agg)
                        })
                        .collect();

                    // Generate the game graph to access the infos for duty emission
                    let game_graph = generate_game_graph(&cfg, &graph_ctx, *graph_data);

                    // Transition to NoncesCollected state
                    self.state = GraphState::NoncesCollected {
                        last_block_height: *last_block_height,
                        graph_data: *graph_data,
                        graph_summary: graph_summary.clone(),
                        pubnonces: pubnonces.clone(),
                        agg_nonces: agg_nonces.clone(),
                        partial_signatures: BTreeMap::new(),
                    };

                    // Emit duties to publish partial signatures
                    let claim_txid = game_graph.claim.as_ref().compute_txid();
                    let graph_inpoints = game_graph.musig_inpoints().pack();
                    let (graph_tweaks, sighashes): (Vec<TaprootTweak>, Vec<Message>) = game_graph
                        .musig_signing_info()
                        .pack()
                        .iter()
                        .map(|m| (m.tweak, m.sighash))
                        .unzip();

                    return Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishGraphPartials {
                            deposit_idx: self.context.deposit_idx(),
                            operator_idx: self.context.operator_idx(),
                            agg_nonces,
                            sighashes,
                            graph_inpoints,
                            graph_tweaks,
                            claim_txid,
                        },
                    ]));
                }

                Ok(GSMOutput::default())
            }
            GraphState::NoncesCollected { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                nonce_received_event.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                nonce_received_event.into(),
                None,
            )),
        }
    }
}
