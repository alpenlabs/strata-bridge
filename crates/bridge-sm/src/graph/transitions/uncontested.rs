use std::{collections::BTreeMap, sync::Arc};

use musig2::{AggNonce, secp256k1::Message, verify_partial};
use strata_bridge_primitives::{
    key_agg::create_agg_ctx, scripts::taproot::TaprootTweak, types::OperatorIdx,
};
use strata_bridge_tx_graph2::{game_graph::DepositParams, musig_functor::GameFunctor};

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::{
        AdaptorsVerifiedEvent, GraphDataGeneratedEvent, GraphNonceReceivedEvent,
        GraphPartialReceivedEvent,
    },
    machine::{GSMOutput, GraphSM, generate_game_graph},
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
                let game_graph = generate_game_graph(&cfg, self.context(), deposit_params);

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
                let game_graph = generate_game_graph(&cfg, self.context(), *graph_data);
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

    pub(crate) fn process_partial_received(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        partial_received_event: GraphPartialReceivedEvent,
    ) -> GSMResult<GSMOutput> {
        // Validate operator_idx is in the operator table
        self.check_operator_idx(partial_received_event.operator_idx, &partial_received_event)?;
        let operator_table_cardinality = self.context().operator_table().cardinality();
        let graph_ctx = self.context().clone();

        let btc_keys: Vec<_> = self
            .context()
            .operator_table()
            .btc_keys()
            .into_iter()
            .collect();

        // Get the operator pubkey
        let operator_pubkey = self
            .context()
            .operator_table
            .idx_to_btc_key(&partial_received_event.operator_idx)
            .expect("validated above");

        match self.state_mut() {
            GraphState::NoncesCollected {
                last_block_height,
                graph_data,
                graph_summary,
                pubnonces,
                agg_nonces,
                partial_signatures,
            } => {
                // Check for duplicate signature submission
                if partial_signatures.contains_key(&partial_received_event.operator_idx) {
                    return Err(GSMError::duplicate(
                        self.state().clone(),
                        partial_received_event.into(),
                    ));
                }

                // Validate the num partial sigs
                if GameFunctor::unpack(
                    partial_received_event.partial_sigs.clone(),
                    operator_table_cardinality,
                )
                .is_none()
                {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        partial_received_event.into(),
                        "Invalid partial singatures provided by operator".to_string(),
                    ));
                }

                // Validate the individual partial sigs
                // Generate the game graph to access signing infos for verification
                let game_graph = generate_game_graph(&cfg, &graph_ctx, *graph_data);
                let signing_infos = game_graph.musig_signing_info().pack();

                let operator_pubnonces = pubnonces
                    .get(&partial_received_event.operator_idx)
                    .expect("operator must have submitted nonce");

                for (i, (signing_info, partial_sig)) in signing_infos
                    .iter()
                    .zip(partial_received_event.partial_sigs.iter())
                    .enumerate()
                {
                    let key_agg_ctx = create_agg_ctx(btc_keys.iter().copied(), &signing_info.tweak)
                        .expect("must be able to create key aggregation context");

                    if verify_partial(
                        &key_agg_ctx,
                        *partial_sig,
                        &agg_nonces[i],
                        operator_pubkey,
                        &operator_pubnonces[i],
                        signing_info.sighash.as_ref(),
                    )
                    .is_err()
                    {
                        return Err(GSMError::rejected(
                            self.state().clone(),
                            partial_received_event.into(),
                            format!("Partial signature verification failed at index {i}"),
                        ));
                    }
                }

                todo!()
            }
            GraphState::GraphSigned { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                partial_received_event.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                partial_received_event.into(),
                None,
            )),
        }
    }
}
