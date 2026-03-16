//! Unit tests for process_nag_received.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::AggNonce;
    use strata_bridge_p2p_types::NagRequestPayload;
    use strata_bridge_primitives::scripts::taproot::TaprootTweak;

    use crate::graph::{
        duties::GraphDuty,
        errors::GSMError,
        events::{GraphEvent, NagReceivedEvent},
        machine::generate_game_graph,
        state::GraphState,
        tests::{
            GraphHandlerOutput, GraphInvalidTransition, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT,
            TEST_ASSIGNEE, TEST_NONPOV_IDX,
            mock_states::{
                adaptors_verified_state, all_state_variants, nonces_collected_state,
                test_graph_generated_state,
            },
            test_deposit_params, test_graph_data, test_graph_invalid_transition, test_graph_sm_cfg,
            test_graph_sm_ctx, test_graph_summary, test_pov_owned_handler_output,
            test_recipient_desc,
            utils::build_nonce_context,
        },
    };

    fn create_nag_event(payload: NagRequestPayload) -> NagReceivedEvent {
        NagReceivedEvent {
            payload,
            sender_operator_idx: TEST_NONPOV_IDX,
        }
    }

    fn expected_publish_graph_nonces_duty(cfg: &crate::graph::config::GraphSMCfg) -> GraphDuty {
        let ctx = test_graph_sm_ctx();
        let game_graph = generate_game_graph(cfg, &ctx, test_deposit_params());
        let graph_inpoints = game_graph.musig_inpoints().pack();
        let graph_tweaks = game_graph
            .musig_signing_info()
            .pack()
            .iter()
            .map(|m| m.tweak)
            .collect::<Vec<TaprootTweak>>();
        let ordered_pubkeys = ctx
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        GraphDuty::PublishGraphNonces {
            graph_idx: ctx.graph_idx(),
            graph_inpoints,
            graph_tweaks,
            ordered_pubkeys,
        }
    }

    fn expected_publish_graph_partials_duty(
        cfg: &crate::graph::config::GraphSMCfg,
        agg_nonces: Vec<AggNonce>,
    ) -> GraphDuty {
        let ctx = test_graph_sm_ctx();
        let game_graph = generate_game_graph(cfg, &ctx, test_deposit_params());
        let graph_inpoints = game_graph.musig_inpoints().pack();
        let claim_txid = game_graph.claim.as_ref().compute_txid();
        let (graph_tweaks, sighashes): (Vec<TaprootTweak>, Vec<_>) = game_graph
            .musig_signing_info()
            .pack()
            .iter()
            .map(|m| (m.tweak, m.sighash))
            .unzip();
        let ordered_pubkeys = ctx
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        GraphDuty::PublishGraphPartials {
            graph_idx: ctx.graph_idx(),
            agg_nonces,
            sighashes,
            graph_inpoints,
            graph_tweaks,
            claim_txid,
            ordered_pubkeys,
        }
    }

    #[test]
    fn test_nag_received_graph_nonces_in_adaptors_verified_emits_publish_graph_nonces() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let expected_duty = expected_publish_graph_nonces_duty(&cfg);

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: adaptors_verified_state(deposit_params, graph_summary),
                event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphNonces {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                })),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_nonces_in_nonces_collected_emits_publish_graph_nonces() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let expected_duty = expected_publish_graph_nonces_duty(&cfg);

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: nonces_collected_state(&nonce_ctx, deposit_params, graph_summary),
                event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphNonces {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                })),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_partials_in_nonces_collected_emits_publish_graph_partials() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let expected_duty =
            expected_publish_graph_partials_duty(&cfg, nonce_ctx.agg_nonces.clone());

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: nonces_collected_state(&nonce_ctx, deposit_params, graph_summary),
                event: GraphEvent::NagReceived(create_nag_event(
                    NagRequestPayload::GraphPartials {
                        graph_idx: test_graph_sm_ctx().graph_idx(),
                    },
                )),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_partials_in_graph_signed_emits_publish_graph_partials() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let expected_duty =
            expected_publish_graph_partials_duty(&cfg, nonce_ctx.agg_nonces.clone());

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: GraphState::GraphSigned {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    graph_data: deposit_params,
                    graph_summary,
                    agg_nonces: nonce_ctx.agg_nonces,
                    signatures: vec![],
                },
                event: GraphEvent::NagReceived(create_nag_event(
                    NagRequestPayload::GraphPartials {
                        graph_idx: test_graph_sm_ctx().graph_idx(),
                    },
                )),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_nonces_rejected_in_graph_signed() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::GraphSigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: deposit_params,
                graph_summary,
                agg_nonces: nonce_ctx.agg_nonces,
                signatures: vec![],
            },
            event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphNonces {
                graph_idx: test_graph_sm_ctx().graph_idx(),
            })),
            expected_error: |e| {
                matches!(
                    e,
                    GSMError::Rejected { reason, .. }
                        if reason.contains(
                            "expected state(s): AdaptorsVerified | NoncesCollected"
                        )
                )
            },
        });
    }

    #[test]
    fn test_nag_received_graph_partials_rejected_in_adaptors_verified() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: adaptors_verified_state(deposit_params, graph_summary),
            event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphPartials {
                graph_idx: test_graph_sm_ctx().graph_idx(),
            })),
            expected_error: |e| {
                matches!(
                    e,
                    GSMError::Rejected { reason, .. }
                        if reason.contains(
                            "expected state(s): NoncesCollected | GraphSigned"
                        )
                )
            },
        });
    }

    #[test]
    fn test_nag_received_graph_data_in_created_emits_generate_graph_data() {
        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: GraphState::Created {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                },
                event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphData {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                })),
                expected_duties: vec![GraphDuty::GenerateGraphData {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                }],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_data_in_graph_generated_emits_generate_graph_data() {
        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: test_graph_generated_state(),
                event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphData {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                })),
                expected_duties: vec![GraphDuty::GenerateGraphData {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                }],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_data_in_adaptors_verified_emits_generate_graph_data() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: adaptors_verified_state(deposit_params, graph_summary),
                event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphData {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                })),
                expected_duties: vec![GraphDuty::GenerateGraphData {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                }],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_data_rejected_in_all_other_states() {
        let invalid_states: Vec<GraphState> = all_state_variants()
            .into_iter()
            .filter(|state| {
                !matches!(
                    state,
                    GraphState::Created { .. }
                        | GraphState::GraphGenerated { .. }
                        | GraphState::AdaptorsVerified { .. }
                )
            })
            .collect();

        for state in invalid_states {
            test_graph_invalid_transition(GraphInvalidTransition {
                from_state: state,
                event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphData {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                })),
                expected_error: |e| {
                    matches!(
                        e,
                        GSMError::Rejected { reason, .. }
                            if reason.contains(
                                "expected state(s): Created | GraphGenerated | AdaptorsVerified"
                            )
                    )
                },
            });
        }
    }

    #[test]
    fn test_nag_received_deposit_domain_payload_is_rejected() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                agg_nonces: vec![],
                signatures: vec![],
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: test_recipient_desc(1),
            },
            event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::DepositNonce {
                deposit_idx: test_graph_sm_ctx().deposit_idx(),
            })),
            expected_error: |e| {
                matches!(
                    e,
                    GSMError::Rejected { reason, .. }
                        if reason.contains("Deposit-domain nag is not applicable to GraphSM")
                )
            },
        });
    }

    #[test]
    fn test_nag_received_graph_nonces_rejected_in_irrelevant_state() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                agg_nonces: vec![],
                signatures: vec![],
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: test_recipient_desc(1),
            },
            event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphNonces {
                graph_idx: test_graph_sm_ctx().graph_idx(),
            })),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_nag_received_graph_partials_rejected_in_irrelevant_state() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::Created {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphPartials {
                graph_idx: test_graph_sm_ctx().graph_idx(),
            })),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_nag_received_graph_nonces_includes_sender_in_rejection_reason() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::Created {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphNonces {
                graph_idx: test_graph_sm_ctx().graph_idx(),
            })),
            expected_error: |e| {
                matches!(
                    e,
                    GSMError::Rejected { reason, .. }
                        if reason.contains("sender_operator_idx")
                )
            },
        });
    }

    #[test]
    fn test_nag_received_graph_partials_in_graph_signed_uses_state_agg_nonces() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let expected_agg_nonces = nonce_ctx.agg_nonces.clone();
        let expected_duty = expected_publish_graph_partials_duty(&cfg, expected_agg_nonces.clone());

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: GraphState::GraphSigned {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    graph_data: deposit_params,
                    graph_summary,
                    agg_nonces: expected_agg_nonces.clone(),
                    signatures: vec![],
                },
                event: GraphEvent::NagReceived(create_nag_event(
                    NagRequestPayload::GraphPartials {
                        graph_idx: test_graph_sm_ctx().graph_idx(),
                    },
                )),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_nag_received_graph_nonces_ignores_partial_collection_progress() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());

        let mut partials = BTreeMap::new();
        partials.insert(TEST_NONPOV_IDX, vec![]);

        test_pov_owned_handler_output(
            cfg.clone(),
            GraphHandlerOutput {
                state: GraphState::NoncesCollected {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    graph_data: deposit_params,
                    graph_summary,
                    pubnonces: nonce_ctx.pubnonces,
                    agg_nonces: nonce_ctx.agg_nonces,
                    partial_signatures: partials,
                },
                event: GraphEvent::NagReceived(create_nag_event(NagRequestPayload::GraphNonces {
                    graph_idx: test_graph_sm_ctx().graph_idx(),
                })),
                expected_duties: vec![expected_publish_graph_nonces_duty(&cfg)],
            },
        );
    }
}
