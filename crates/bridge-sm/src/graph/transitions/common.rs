use std::sync::Arc;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::NewBlockEvent,
    machine::{GSMOutput, GraphSM, unpack_game},
    state::GraphState,
    watchtower::watchtower_slot_for_operator,
};

impl GraphSM {
    /// Processes information about new blocks and applies any updates related to block height
    /// timeouts
    pub(crate) fn notify_new_block(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        new_block_event: NewBlockEvent,
    ) -> GSMResult<GSMOutput> {
        let last_processed_block_height = self.state().last_processed_block_height();
        if last_processed_block_height.is_some_and(|height| *height >= new_block_event.block_height)
        {
            return Err(GSMError::rejected(
                self.state().clone(),
                new_block_event.into(),
                "Rejecting already processed block".to_string(),
            ));
        }

        let graph_ctx = self.context().clone();

        match self.state_mut() {
            GraphState::Created {
                last_block_height, ..
            }
            | GraphState::GraphGenerated {
                last_block_height, ..
            }
            | GraphState::AdaptorsVerified {
                last_block_height, ..
            }
            | GraphState::NoncesCollected {
                last_block_height, ..
            }
            | GraphState::GraphSigned {
                last_block_height, ..
            }
            | GraphState::Fulfilled {
                last_block_height, ..
            } => {
                *last_block_height = new_block_event.block_height;
                Ok(GSMOutput::new())
            }

            GraphState::Assigned {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                deadline,
                ..
            } => {
                // If deadline has elapsed, revert to GraphSigned state
                if new_block_event.block_height >= *deadline {
                    self.state = GraphState::GraphSigned {
                        last_block_height: new_block_event.block_height,
                        graph_data: *graph_data,
                        graph_summary: graph_summary.clone(),
                        agg_nonces: None,
                        signatures: signatures.clone(),
                    };
                } else {
                    *last_block_height = new_block_event.block_height;
                }

                Ok(GSMOutput::new())
            }

            GraphState::Claimed {
                last_block_height,
                graph_data,
                claim_block_height,
                signatures,
                ..
            } => {
                // Extract context values before the match to avoid borrow conflicts
                let graph_data = *graph_data;
                let claim_height = *claim_block_height;
                *last_block_height = new_block_event.block_height;

                let contest_timeout = u64::from(cfg.game_graph_params.contest_timelock.value());

                if new_block_event.block_height > claim_height + contest_timeout {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, graph_data, signatures);
                    let signed_uncontested_payout_tx = game_graph
                        .uncontested_payout
                        .finalize(sigs.uncontested_payout);

                    return Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishUncontestedPayout {
                            signed_uncontested_payout_tx,
                        },
                    ]));
                }

                Ok(GSMOutput::new())
            }

            GraphState::Contested {
                last_block_height,
                contest_block_height,
                graph_data,
                signatures,
                ..
            } => {
                *last_block_height = new_block_event.block_height;
                let payout_timelock =
                    u64::from(cfg.game_graph_params.contested_payout_timelock.value());
                let proof_timelock = u64::from(cfg.game_graph_params.proof_timelock.value());

                if new_block_event.block_height > *contest_block_height + payout_timelock {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_slash_tx = game_graph.slash.finalize(sigs.slash);

                    return Ok(GSMOutput::with_duties(vec![GraphDuty::PublishSlash {
                        signed_slash_tx,
                    }]));
                }

                if new_block_event.block_height > *contest_block_height + proof_timelock {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_timeout_tx = game_graph
                        .bridge_proof_timeout
                        .finalize(sigs.bridge_proof_timeout);

                    return Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishBridgeProofTimeout { signed_timeout_tx },
                    ]));
                }

                Ok(GSMOutput::new())
            }

            GraphState::BridgeProofPosted {
                last_block_height,
                contest_block_height,
                graph_data,
                signatures,
                ..
            } => {
                *last_block_height = new_block_event.block_height;
                let payout_timelock =
                    u64::from(cfg.game_graph_params.contested_payout_timelock.value());
                let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
                let is_own_graph = graph_ctx.operator_idx() == graph_ctx.operator_table().pov_idx();

                // check if slashing is possible
                if !is_own_graph
                    && new_block_event.block_height > *contest_block_height + payout_timelock
                {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_slash_tx = game_graph.slash.finalize(sigs.slash);

                    return Ok(GSMOutput::with_duties(vec![GraphDuty::PublishSlash {
                        signed_slash_tx,
                    }]));
                }

                // check if contested payout is possible
                if is_own_graph
                    && new_block_event.block_height > *contest_block_height + ack_timelock
                {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_contested_payout_tx =
                        game_graph.contested_payout.finalize(sigs.contested_payout);

                    return Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishContestedPayout {
                            signed_contested_payout_tx,
                        },
                    ]));
                }

                Ok(GSMOutput::new())
            }

            GraphState::BridgeProofTimedout {
                last_block_height,
                contest_block_height,
                graph_data,
                signatures,
                ..
            } => {
                *last_block_height = new_block_event.block_height;
                let payout_timelock =
                    u64::from(cfg.game_graph_params.contested_payout_timelock.value());

                if new_block_event.block_height > *contest_block_height + payout_timelock {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_slash_tx = game_graph.slash.finalize(sigs.slash);

                    return Ok(GSMOutput::with_duties(vec![GraphDuty::PublishSlash {
                        signed_slash_tx,
                    }]));
                }

                Ok(GSMOutput::new())
            }

            GraphState::CounterProofPosted {
                last_block_height,
                graph_data,
                signatures,
                contest_block_height,
                counterproofs_and_confs,
                ..
            } => {
                *last_block_height = new_block_event.block_height;

                let payout_timelock =
                    u64::from(cfg.game_graph_params.contested_payout_timelock.value());
                let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
                let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());
                let pov_idx = graph_ctx.operator_table().pov_idx();
                let is_own_graph = graph_ctx.operator_idx() == pov_idx;

                // If pov operator doesn't own the graph, they will attempt to slash payout
                // timelock has expired.
                if !is_own_graph
                    && new_block_event.block_height > *contest_block_height + payout_timelock
                {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_slash_tx = game_graph.slash.finalize(sigs.slash);

                    return Ok(GSMOutput::with_duties(vec![GraphDuty::PublishSlash {
                        signed_slash_tx,
                    }]));
                }

                // If pov operator owns the graph, they will attempt to publish the contested
                // payout if the ack timelock has expired.
                if is_own_graph
                    && new_block_event.block_height > *contest_block_height + ack_timelock
                {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_contested_payout_tx =
                        game_graph.contested_payout.finalize(sigs.contested_payout);

                    return Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishContestedPayout {
                            signed_contested_payout_tx,
                        },
                    ]));
                }

                // If the pov operator has NOT submitted a counterproof, return early with no
                // duties.
                let Some((_, pov_counterproof_height)) = counterproofs_and_confs.get(&pov_idx)
                else {
                    return Ok(GSMOutput::new());
                };

                // There is no-op for non-graph owners until the nack timelock has expired. The
                // graph owner should publish counterproof nack but this duty is handled in the
                // process_counterproof_confirmed and retry. Hence, return with no duties.
                if new_block_event.block_height <= pov_counterproof_height + nack_timelock {
                    return Ok(GSMOutput::new());
                }

                // NACK window has elapsed, so the counterprover can now publish ACK.
                let graph_idx = graph_ctx.graph_idx();
                let graph_owner_idx = graph_ctx.operator_idx();
                let watchtower_slot = watchtower_slot_for_operator(graph_owner_idx, pov_idx)
                    .unwrap_or_else(|| {
                        tracing::error!(
                            ?graph_idx,
                            graph_owner_idx,
                            pov_idx,
                            block_height = new_block_event.block_height,
                            "recorded POV counterproof but missing watchtower slot mapping"
                        );
                        panic!(
                            "recorded POV counterproof but missing watchtower slot \
                             (graph_idx={graph_idx:?}, graph_owner_idx={graph_owner_idx}, pov_idx={pov_idx},
                             block_height={})",
                            new_block_event.block_height,
                        )
                    });

                let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                let counterproof_graph =
                    game_graph
                        .counterproofs
                        .get(watchtower_slot)
                        .unwrap_or_else(|| {
                            tracing::error!(
                                ?graph_idx,
                                graph_owner_idx,
                                pov_idx,
                                block_height = new_block_event.block_height,
                                watchtower_slot,
                                "missing counterproof graph for computed watchtower slot"
                            );
                            panic!(
                                "missing counterproof graph for computed watchtower slot (graph_idx={graph_idx:?}, \
                                    graph_owner_idx={graph_owner_idx}, pov_idx={pov_idx}, block_height={}, slot={watchtower_slot})",
                                new_block_event.block_height,
                            )
                        });

                let watchtower_sigs = sigs.watchtowers.get(watchtower_slot).unwrap_or_else(|| {
                    tracing::error!(
                        ?graph_idx,
                        graph_owner_idx,
                        pov_idx,
                        block_height = new_block_event.block_height,
                        watchtower_slot,
                        "missing watchtower signatures for computed watchtower slot"
                    );
                    panic!(
                        "missing watchtower signatures for computed watchtower slot \
                         (graph_idx={graph_idx:?}, graph_owner_idx={graph_owner_idx}, pov_idx={pov_idx}, block_height={}, slot={watchtower_slot})",
                        new_block_event.block_height,
                    )
                });

                let signed_counter_proof_ack_tx = counterproof_graph
                    .counterproof_ack
                    .clone()
                    .finalize(watchtower_sigs.counterproof_ack);

                Ok(GSMOutput::with_duties(vec![
                    GraphDuty::PublishCounterProofAck {
                        signed_counter_proof_ack_tx,
                    },
                ]))
            }

            // TODO: <https://atlassian.alpenlabs.net/browse/STR-2342>
            GraphState::AllNackd { .. } => todo!(""),

            GraphState::Acked {
                last_block_height,
                graph_data,
                signatures,
                contest_block_height,
                ..
            } => {
                *last_block_height = new_block_event.block_height;
                let payout_timelock =
                    u64::from(cfg.game_graph_params.contested_payout_timelock.value());
                let is_own_graph = graph_ctx.operator_idx() == graph_ctx.operator_table().pov_idx();

                // Non-graph owners publish slash once the payout timelock has expired.
                if !is_own_graph
                    && new_block_event.block_height > *contest_block_height + payout_timelock
                {
                    let (game_graph, sigs) = unpack_game(&cfg, &graph_ctx, *graph_data, signatures);
                    let signed_slash_tx = game_graph.slash.finalize(sigs.slash);

                    return Ok(GSMOutput::with_duties(vec![GraphDuty::PublishSlash {
                        signed_slash_tx,
                    }]));
                }

                Ok(GSMOutput::new())
            }

            // Terminal states do not process new blocks
            GraphState::Withdrawn { .. }
            | GraphState::Slashed { .. }
            | GraphState::Aborted { .. } => Err(GSMError::rejected(
                self.state().clone(),
                new_block_event.into(),
                "New blocks irrelevant in terminal state",
            )),
        }
    }
}
