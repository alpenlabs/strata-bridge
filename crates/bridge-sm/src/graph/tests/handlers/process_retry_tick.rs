//! Unit tests for process_retry_tick.
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;
    use strata_bridge_tx_graph::game_graph::GameConnectors;

    use crate::graph::{
        duties::GraphDuty,
        events::{GraphEvent, RetryTickEvent},
        machine::{GraphSM, generate_game_graph},
        state::GraphState,
        tests::{
            FULFILLMENT_BLOCK_HEIGHT, GraphHandlerOutput, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT,
            TEST_ASSIGNEE, TEST_POV_IDX, create_nonpov_sm, create_sm,
            mock_states::{
                assigned_state, claimed_state, contested_state,
                counter_proof_posted_state, counter_proof_posted_without_refuted_proof_state,
                graph_signed_state, terminal_states, test_graph_generated_state,
                test_nonce_context,
            },
            test_deposit_params, test_graph_sm_cfg, test_graph_summary,
            test_nonpov_owned_handler_output, test_pov_owned_handler_output, test_recipient_desc,
        },
    };

    fn expected_pov_counterproof_idx(sm: &GraphSM) -> usize {
        let graph_owner_idx = sm.context().operator_idx();
        let pov_operator_idx = sm.context().operator_table().pov_idx();

        sm.context()
            .operator_table()
            .operator_idxs()
            .into_iter()
            .filter(|idx| *idx != graph_owner_idx)
            .position(|idx| idx == pov_operator_idx)
            .expect("expected PoV operator to appear in counterproof ordering")
    }

    #[test]
    fn test_retry_tick_emits_verify_adaptors_in_graph_generated_for_nonpov_graph() {
        let cfg = test_graph_sm_cfg();
        let state = test_graph_generated_state();
        let sm = create_nonpov_sm(state.clone());

        let GraphState::GraphGenerated { graph_data, .. } = state else {
            panic!("expected GraphGenerated state");
        };
        let game_graph = generate_game_graph(&cfg, sm.context(), &graph_data);
        let pov_operator_idx = sm.context().operator_table().pov_idx();
        let pov_counterproof_idx = expected_pov_counterproof_idx(&sm);
        let expected_sighashes = game_graph.counterproofs[pov_counterproof_idx]
            .counterproof
            .sighashes();
        let expected_adaptor_pubkey = graph_data.adaptor_pubkeys[pov_counterproof_idx];
        let expected_fault_pubkey = graph_data.fault_pubkeys[pov_counterproof_idx];

        test_nonpov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: test_graph_generated_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![GraphDuty::VerifyAdaptors {
                    graph_idx: sm.context().graph_idx(),
                    watchtower_idx: pov_operator_idx,
                    sighashes: expected_sighashes,
                    adaptor_pubkey: expected_adaptor_pubkey,
                    fault_pubkey: expected_fault_pubkey,
                }],
            },
        );
    }

    #[test]
    fn test_retry_tick_emits_publish_claim_in_fulfilled_when_failed_for_pov_graph() {
        let cfg = test_graph_sm_cfg();
        let state = GraphState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            coop_payout_failed: true,
            assignee: TEST_POV_IDX,
            signatures: Default::default(),
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
        };
        let sm = create_sm(state.clone());
        let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![GraphDuty::PublishClaim {
                    claim_tx: game_graph.claim,
                }],
            },
        );
    }

    #[test]
    fn test_retry_tick_emits_bridge_proof_in_contested_for_pov_graph() {
        let cfg = test_graph_sm_cfg();
        let state = contested_state();
        let sm = create_sm(state.clone());
        // This retry path only emits a bridge proof duty for the PoV-owned graph.
        assert_eq!(
            sm.context().operator_idx(),
            sm.context().operator_table().pov_idx()
        );

        let expected_duty = {
            let GraphState::Contested {
                graph_data,
                graph_summary,
                ..
            } = &state
            else {
                panic!("expected Contested state");
            };

            let setup_params = sm.context().generate_setup_params(&cfg, graph_data);
            let connectors =
                GameConnectors::new(graph_data.game_index, &cfg.game_graph_params, &setup_params);

            GraphDuty::GenerateAndPublishBridgeProof {
                graph_idx: sm.context().graph_idx(),
                contest_txid: graph_summary.contest,
                game_index: graph_data.game_index,
                contest_proof_connector: connectors.contest_proof,
            }
        };

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![expected_duty],
            },
        );
    }

    // ===== Guard negative tests =====

    #[test]
    fn test_retry_tick_noop_in_graph_generated_for_pov_graph() {
        // POV owns this graph, no need to verify own adaptors
        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: test_graph_generated_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_fulfilled_for_nonpov_graph() {
        // Non-POV graph should not emit claim even if coop payout failed
        let state = GraphState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            coop_payout_failed: true,
            assignee: TEST_ASSIGNEE,
            signatures: Default::default(),
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
        };

        test_nonpov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_fulfilled_when_coop_payout_not_failed() {
        // POV graph but coop payout hasn't failed yet
        let state = GraphState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            coop_payout_failed: false,
            assignee: TEST_POV_IDX,
            signatures: Default::default(),
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
        };

        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_fulfilled_for_pov_graph_when_not_assignee() {
        let state = GraphState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            coop_payout_failed: true,
            assignee: TEST_ASSIGNEE,
            signatures: Default::default(),
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
        };

        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    // ===== Non-retriable state no-op tests =====

    #[test]
    fn test_retry_tick_noop_for_non_retriable_states() {
        let cfg = test_graph_sm_cfg();

        let non_retriable_states = vec![
            GraphState::Created {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            GraphState::AdaptorsVerified {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                pubnonces: Default::default(),
            },
            GraphState::NoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                pubnonces: Default::default(),
                agg_nonces: Default::default(),
                partial_signatures: Default::default(),
            },
            {
                let (_, _, nonce_ctx) = test_nonce_context();
                graph_signed_state(&nonce_ctx)
            },
            assigned_state(TEST_ASSIGNEE, LATER_BLOCK_HEIGHT, test_recipient_desc(1)),
        ];

        for state in non_retriable_states {
            test_pov_owned_handler_output(
                cfg.clone(),
                GraphHandlerOutput {
                    state,
                    event: GraphEvent::RetryTick(RetryTickEvent),
                    expected_duties: vec![],
                },
            );
        }

        for state in terminal_states() {
            test_pov_owned_handler_output(
                cfg.clone(),
                GraphHandlerOutput {
                    state,
                    event: GraphEvent::RetryTick(RetryTickEvent),
                    expected_duties: vec![],
                },
            );
        }
    }

    // ===== Ownership-specific no-ops for contested-path states =====

    #[test]
    fn test_retry_tick_noop_in_claimed_with_valid_fulfillment() {
        // Claimed with valid fulfillment txid - no contest needed
        let state = claimed_state(LATER_BLOCK_HEIGHT, generate_txid(), Default::default());

        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_contested_for_nonpov_graph() {
        test_nonpov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: contested_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    // ===== CounterProofPosted retry tick tests =====

    #[test]
    fn test_retry_tick_emits_bridge_proof_in_counter_proof_posted_for_pov_graph_when_no_refuted_proof()
    {
        let cfg = test_graph_sm_cfg();
        let state = counter_proof_posted_without_refuted_proof_state();
        let sm = create_sm(state.clone());

        let expected_duty = {
            let GraphState::CounterProofPosted {
                graph_data,
                graph_summary,
                ..
            } = &state
            else {
                panic!("expected CounterProofPosted state");
            };

            let setup_params = sm.context().generate_setup_params(&cfg, graph_data);
            let connectors =
                GameConnectors::new(graph_data.game_index, &cfg.game_graph_params, &setup_params);

            GraphDuty::GenerateAndPublishBridgeProof {
                graph_idx: sm.context().graph_idx(),
                contest_txid: graph_summary.contest,
                game_index: graph_data.game_index,
                contest_proof_connector: connectors.contest_proof,
            }
        };

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_counter_proof_posted_for_pov_graph_when_refuted_proof_present() {
        // Owner has already posted a bridge proof — retry should not re-emit one.
        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: counter_proof_posted_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_counter_proof_posted_for_nonpov_graph_when_no_refuted_proof() {
        test_nonpov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: counter_proof_posted_without_refuted_proof_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }
}
