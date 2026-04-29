//! Unit tests for process_retry_tick.
#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use strata_bridge_primitives::types::OperatorIdx;
    use strata_bridge_test_utils::bitcoin::generate_txid;
    use strata_bridge_tx_graph::{
        game_graph::GameConnectors,
        musig_functor::GameFunctor,
        transactions::prelude::{CounterproofNackData, CounterproofNackTx},
    };
    use strata_predicate::PredicateKey;

    use crate::graph::{
        duties::GraphDuty,
        events::{GraphEvent, RetryTickEvent},
        machine::{GraphSM, generate_game_graph},
        state::{CounterproofData, GraphState},
        tests::{
            FULFILLMENT_BLOCK_HEIGHT, GraphHandlerOutput, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT,
            N_TEST_OPERATORS, TEST_ASSIGNEE, TEST_NONPOV_IDX, TEST_POV_IDX,
            build_test_graph_summary, create_nonpov_sm, create_sm, dummy_proof_receipt,
            mock_game_signatures,
            mock_states::{
                assigned_state, bridge_proof_posted_state, bridge_proof_posted_state_with,
                claimed_state, contested_state, counter_proof_posted_state,
                counter_proof_posted_without_refuted_proof_state, graph_signed_state,
                terminal_states, test_graph_generated_state, test_nonce_context,
            },
            test_completed_signatures, test_deposit_params, test_graph_sm_cfg, test_graph_summary,
            test_nonpov_owned_handler_output, test_pov_owned_handler_output, test_recipient_desc,
        },
        watchtower::watchtower_slot_for_operator,
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

    // ===== BridgeProofPosted retry tick tests =====

    #[test]
    fn test_retry_tick_emits_counterproof_in_bridge_proof_posted_for_nonpov_graph_with_invalid_proof()
     {
        let mut cfg = (*test_graph_sm_cfg()).clone();
        cfg.bridge_proof_predicate = PredicateKey::never_accept();
        let cfg = Arc::new(cfg);

        let sm = create_nonpov_sm(bridge_proof_posted_state());
        let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let state = bridge_proof_posted_state_with(LATER_BLOCK_HEIGHT, signatures);

        let expected_duty = {
            let GraphState::BridgeProofPosted {
                graph_data,
                signatures,
                proof,
                ..
            } = &state
            else {
                panic!("expected BridgeProofPosted state");
            };

            let game_graph = generate_game_graph(&cfg, sm.context(), graph_data);
            let watchtower_idx = watchtower_slot_for_operator(
                sm.context().operator_idx(),
                sm.context().operator_table().pov_idx(),
            )
            .expect("watchtower slot must exist");

            let counterproof_graph = &game_graph.counterproofs[watchtower_idx];
            let n_of_n_signature =
                GameFunctor::unpack(signatures.clone(), sm.context().watchtower_pubkeys().len())
                    .expect("unpack failed")
                    .watchtowers[watchtower_idx]
                    .counterproof[0];

            GraphDuty::GenerateAndPublishCounterProof {
                graph_idx: sm.context().graph_idx(),
                counterproof_tx: counterproof_graph.counterproof.clone(),
                watchtower_idx: watchtower_idx as OperatorIdx,
                n_of_n_signature,
                proof: proof.clone(),
            }
        };

        test_nonpov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_bridge_proof_posted_for_pov_graph() {
        let mut cfg = (*test_graph_sm_cfg()).clone();
        cfg.bridge_proof_predicate = PredicateKey::never_accept();

        test_pov_owned_handler_output(
            Arc::new(cfg),
            GraphHandlerOutput {
                state: bridge_proof_posted_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_bridge_proof_posted_when_proof_valid() {
        // Default cfg uses always_accept predicate, so proof is valid
        test_nonpov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: bridge_proof_posted_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    // ===== CounterProofPosted retry tick tests =====

    fn counter_proof_posted_state_with_counterproofs(
        counterprover_idxs: &[OperatorIdx],
        nacked_idxs: &[OperatorIdx],
    ) -> GraphState {
        let summary = build_test_graph_summary(N_TEST_OPERATORS - 1);
        let counterproofs_and_confs = counterprover_idxs
            .iter()
            .map(|counterprover_idx| {
                let watchtower_slot =
                    watchtower_slot_for_operator(TEST_POV_IDX, *counterprover_idx)
                        .expect("counterprover should have a watchtower slot");
                (
                    *counterprover_idx,
                    CounterproofData {
                        txid: summary.counterproofs[watchtower_slot].counterproof,
                        conf_height: LATER_BLOCK_HEIGHT,
                        completed_signatures: test_completed_signatures(),
                    },
                )
            })
            .collect();

        GraphState::CounterProofPosted {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: summary,
            signatures: Default::default(),
            fulfillment_txid: Some(generate_txid()),
            contest_block_height: LATER_BLOCK_HEIGHT,
            refuted_proof: None,
            counterproofs_and_confs,
            counterproof_nacks: nacked_idxs
                .iter()
                .map(|counterprover_idx| (*counterprover_idx, generate_txid()))
                .collect(),
        }
    }

    fn counter_proof_posted_state_with_pending_nacks() -> GraphState {
        counter_proof_posted_state_with_counterproofs(&[TEST_NONPOV_IDX], &[])
    }

    fn expected_late_bridge_proof_duty(
        cfg: &Arc<crate::graph::config::GraphSMCfg>,
        sm: &GraphSM,
        state: &GraphState,
    ) -> GraphDuty {
        let GraphState::CounterProofPosted {
            graph_data,
            graph_summary,
            ..
        } = state
        else {
            panic!("expected CounterProofPosted state");
        };

        let setup_params = sm.context().generate_setup_params(cfg, graph_data);
        let connectors =
            GameConnectors::new(graph_data.game_index, &cfg.game_graph_params, &setup_params);

        GraphDuty::GenerateAndPublishBridgeProof {
            graph_idx: sm.context().graph_idx(),
            contest_txid: graph_summary.contest,
            game_index: graph_data.game_index,
            contest_proof_connector: connectors.contest_proof,
        }
    }

    fn expected_counterproof_nack_duty(
        cfg: &Arc<crate::graph::config::GraphSMCfg>,
        sm: &GraphSM,
        state: &GraphState,
        counterprover_idx: OperatorIdx,
    ) -> GraphDuty {
        let GraphState::CounterProofPosted {
            graph_data,
            counterproofs_and_confs,
            ..
        } = state
        else {
            panic!("expected CounterProofPosted state");
        };

        let setup_params = sm.context().generate_setup_params(cfg, graph_data);
        let connectors =
            GameConnectors::new(graph_data.game_index, &cfg.game_graph_params, &setup_params);

        let watchtower_slot = watchtower_slot_for_operator(
            sm.context().operator_table().pov_idx(),
            counterprover_idx,
        )
        .unwrap();

        let data = counterproofs_and_confs.get(&counterprover_idx).unwrap();
        let counterproof_connector = connectors.counterproof[watchtower_slot];
        let nack_data = CounterproofNackData {
            counterproof_txid: data.txid,
        };
        let counterproof_nack_tx = CounterproofNackTx::new(nack_data, counterproof_connector);

        GraphDuty::PublishCounterProofNack {
            deposit_idx: sm.context().deposit_idx(),
            counterprover_idx,
            completed_signatures: data.completed_signatures,
            counterproof_nack_tx,
        }
    }

    #[test]
    fn test_retry_tick_emits_bridge_proof_in_counter_proof_posted_for_pov_graph_when_no_refuted_proof()
     {
        let cfg = test_graph_sm_cfg();
        let state = counter_proof_posted_without_refuted_proof_state();
        let sm = create_sm(state.clone());
        let expected_duty = expected_late_bridge_proof_duty(&cfg, &sm, &state);

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
    fn test_retry_tick_emits_bridge_proof_and_nack_in_counter_proof_posted_for_pov_graph() {
        // Owner has not posted a bridge proof AND a watchtower's counterproof is awaiting NACK.
        // Both duties should fire on the same retry tick.
        let cfg = test_graph_sm_cfg();
        let state = counter_proof_posted_state_with_pending_nacks();
        let sm = create_sm(state.clone());
        let expected_duties = vec![
            expected_late_bridge_proof_duty(&cfg, &sm, &state),
            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),
        ];

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties,
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
    fn test_retry_tick_emits_nack_in_counter_proof_posted_for_pov_graph_when_refuted_proof_present()
    {
        let cfg = test_graph_sm_cfg();
        let mut state = counter_proof_posted_state_with_pending_nacks();
        if let GraphState::CounterProofPosted { refuted_proof, .. } = &mut state {
            *refuted_proof = Some(dummy_proof_receipt());
        }
        let sm = create_sm(state.clone());
        let expected_duty = expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX);

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

    #[test]
    fn test_retry_tick_emits_counterproof_in_counter_proof_posted_for_nonpov_graph_with_invalid_refuted_proof()
     {
        const OTHER_COUNTERPROVER_IDX: OperatorIdx = 2;

        let mut cfg = (*test_graph_sm_cfg()).clone();
        cfg.bridge_proof_predicate = PredicateKey::never_accept();
        let cfg = Arc::new(cfg);

        let sm = create_nonpov_sm(counter_proof_posted_state());
        let graph_data = test_deposit_params();
        let game_graph = generate_game_graph(&cfg, sm.context(), &graph_data);
        let graph_summary = game_graph.summarize();
        let signatures = mock_game_signatures(&game_graph);

        let other_watchtower_idx =
            watchtower_slot_for_operator(sm.context().operator_idx(), OTHER_COUNTERPROVER_IDX)
                .expect("other counterprover should have a watchtower slot");
        let other_counterproof_txid =
            graph_summary.counterproofs[other_watchtower_idx].counterproof;
        let state = GraphState::CounterProofPosted {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data,
            graph_summary,
            signatures: signatures.clone(),
            fulfillment_txid: Some(generate_txid()),
            contest_block_height: LATER_BLOCK_HEIGHT,
            refuted_proof: Some(dummy_proof_receipt()),
            counterproofs_and_confs: BTreeMap::from([(
                OTHER_COUNTERPROVER_IDX,
                CounterproofData {
                    txid: other_counterproof_txid,
                    conf_height: LATER_BLOCK_HEIGHT,
                    completed_signatures: test_completed_signatures(),
                },
            )]),
            counterproof_nacks: BTreeMap::new(),
        };

        assert!(
            !matches!(
                &state,
                GraphState::CounterProofPosted {
                    counterproofs_and_confs,
                    ..
                } if counterproofs_and_confs.contains_key(&TEST_NONPOV_IDX)
            ),
            "local counterproof should be missing from confirmed counterproofs"
        );

        let expected_duty = {
            let GraphState::CounterProofPosted {
                graph_data,
                signatures,
                refuted_proof: Some(proof),
                ..
            } = &state
            else {
                panic!("expected CounterProofPosted state with refuted proof");
            };

            let game_graph = generate_game_graph(&cfg, sm.context(), graph_data);
            let watchtower_idx = watchtower_slot_for_operator(
                sm.context().operator_idx(),
                sm.context().operator_table().pov_idx(),
            )
            .expect("watchtower slot must exist");

            let counterproof_graph = &game_graph.counterproofs[watchtower_idx];
            let n_of_n_signature =
                GameFunctor::unpack(signatures.clone(), sm.context().watchtower_pubkeys().len())
                    .expect("unpack failed")
                    .watchtowers[watchtower_idx]
                    .counterproof[0];

            GraphDuty::GenerateAndPublishCounterProof {
                graph_idx: sm.context().graph_idx(),
                counterproof_tx: counterproof_graph.counterproof.clone(),
                watchtower_idx: watchtower_idx as OperatorIdx,
                n_of_n_signature,
                proof: proof.clone(),
            }
        };

        test_nonpov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![expected_duty],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_counter_proof_posted_for_nonpov_graph_when_local_counterproof_confirmed()
     {
        let mut cfg = (*test_graph_sm_cfg()).clone();
        cfg.bridge_proof_predicate = PredicateKey::never_accept();
        let cfg = Arc::new(cfg);

        let sm = create_nonpov_sm(counter_proof_posted_state());
        let graph_data = test_deposit_params();
        let game_graph = generate_game_graph(&cfg, sm.context(), &graph_data);
        let graph_summary = game_graph.summarize();
        let signatures = mock_game_signatures(&game_graph);

        let local_watchtower_idx = watchtower_slot_for_operator(
            sm.context().operator_idx(),
            sm.context().operator_table().pov_idx(),
        )
        .expect("local counterprover should have a watchtower slot");
        let local_counterproof_txid =
            graph_summary.counterproofs[local_watchtower_idx].counterproof;

        test_nonpov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: GraphState::CounterProofPosted {
                    last_block_height: LATER_BLOCK_HEIGHT,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid: Some(generate_txid()),
                    contest_block_height: LATER_BLOCK_HEIGHT,
                    refuted_proof: Some(dummy_proof_receipt()),
                    counterproofs_and_confs: BTreeMap::from([(
                        TEST_NONPOV_IDX,
                        CounterproofData {
                            txid: local_counterproof_txid,
                            conf_height: LATER_BLOCK_HEIGHT,
                            completed_signatures: test_completed_signatures(),
                        },
                    )]),
                    counterproof_nacks: BTreeMap::new(),
                },
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_counter_proof_posted_for_nonpov_graph_when_proof_valid() {
        test_nonpov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: counter_proof_posted_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_counter_proof_posted_for_nonpov_graph_when_proof_valid_and_local_counterproof_confirmed()
     {
        let cfg = test_graph_sm_cfg();
        let sm = create_nonpov_sm(counter_proof_posted_state());
        let graph_data = test_deposit_params();
        let game_graph = generate_game_graph(&cfg, sm.context(), &graph_data);
        let graph_summary = game_graph.summarize();
        let signatures = mock_game_signatures(&game_graph);

        let local_watchtower_idx = watchtower_slot_for_operator(
            sm.context().operator_idx(),
            sm.context().operator_table().pov_idx(),
        )
        .expect("local counterprover should have a watchtower slot");
        let local_counterproof_txid =
            graph_summary.counterproofs[local_watchtower_idx].counterproof;

        test_nonpov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state: GraphState::CounterProofPosted {
                    last_block_height: LATER_BLOCK_HEIGHT,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid: Some(generate_txid()),
                    contest_block_height: LATER_BLOCK_HEIGHT,
                    refuted_proof: Some(dummy_proof_receipt()),
                    counterproofs_and_confs: BTreeMap::from([(
                        TEST_NONPOV_IDX,
                        CounterproofData {
                            txid: local_counterproof_txid,
                            conf_height: LATER_BLOCK_HEIGHT,
                            completed_signatures: test_completed_signatures(),
                        },
                    )]),
                    counterproof_nacks: BTreeMap::new(),
                },
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_counter_proof_posted_for_nonpov_graph() {
        test_nonpov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: counter_proof_posted_state_with_pending_nacks(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }

    #[test]
    fn test_retry_tick_emits_only_bridge_proof_when_counterproof_already_nacked() {
        // Counterproof is already NACK'd, but the owner still has not posted a bridge proof,
        // so only the late bridge proof duty fires.
        let cfg = test_graph_sm_cfg();
        let state =
            counter_proof_posted_state_with_counterproofs(&[TEST_NONPOV_IDX], &[TEST_NONPOV_IDX]);
        let sm = create_sm(state.clone());
        let expected_duty = expected_late_bridge_proof_duty(&cfg, &sm, &state);

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
    fn test_retry_tick_emits_bridge_proof_and_nacks_for_multiple_pending_counterproofs() {
        const SECOND_NONPOV_IDX: OperatorIdx = 2;

        let cfg = test_graph_sm_cfg();
        let state = counter_proof_posted_state_with_counterproofs(
            &[TEST_NONPOV_IDX, SECOND_NONPOV_IDX],
            &[],
        );
        let sm = create_sm(state.clone());
        let expected_duties = vec![
            expected_late_bridge_proof_duty(&cfg, &sm, &state),
            expected_counterproof_nack_duty(&cfg, &sm, &state, TEST_NONPOV_IDX),
            expected_counterproof_nack_duty(&cfg, &sm, &state, SECOND_NONPOV_IDX),
        ];

        test_pov_owned_handler_output(
            cfg,
            GraphHandlerOutput {
                state,
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties,
            },
        );
    }

    #[test]
    fn test_retry_tick_noop_in_counter_proof_posted_when_no_pending_nacks() {
        test_pov_owned_handler_output(
            test_graph_sm_cfg(),
            GraphHandlerOutput {
                state: counter_proof_posted_state(),
                event: GraphEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            },
        );
    }
}
