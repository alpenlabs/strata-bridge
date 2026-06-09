//! Unit tests for signals received from the Deposit SM.
#[cfg(test)]
mod tests {
    use bitcoin::Txid;
    use strata_bridge_primitives::types::{DepositIdx, GraphIdx};
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::GraphEvent,
            machine::{GraphSM, generate_game_graph},
            state::{AbortReason, GraphState},
            tests::{
                FULFILLMENT_BLOCK_HEIGHT, GraphInvalidTransition, GraphTransition,
                INITIAL_BLOCK_HEIGHT, TEST_POV_IDX, create_nonpov_sm, get_state,
                mock_states::{all_state_variants, fulfilled_state, pre_signing_states},
                test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
                test_graph_sm_ctx, test_graph_summary,
            },
        },
        signals::DepositToGraph,
        state_machine::StateMachine,
        testing::{fixtures::TEST_DEPOSIT_IDX, test_transition},
    };

    fn coop_payout_failed_event() -> GraphEvent {
        GraphEvent::DepositMessage(DepositToGraph::CooperativePayoutFailed {
            assignee: TEST_POV_IDX,
            graph_idx: GraphIdx {
                deposit: TEST_DEPOSIT_IDX,
                operator: TEST_POV_IDX,
            },
        })
    }

    fn deposit_request_taken_back_event(
        deposit_idx: DepositIdx,
        takeback_txid: Txid,
    ) -> GraphEvent {
        GraphEvent::DepositMessage(DepositToGraph::DepositRequestTakenBack {
            deposit_idx,
            takeback_txid,
        })
    }

    fn is_after_fulfilled_state(state: &GraphState) -> bool {
        matches!(
            state,
            GraphState::Claimed { .. }
                | GraphState::Contested { .. }
                | GraphState::BridgeProofPosted { .. }
                | GraphState::BridgeProofTimedout { .. }
                | GraphState::CounterProofPosted { .. }
                | GraphState::AllNackd { .. }
                | GraphState::Acked { .. }
                | GraphState::Withdrawn { .. }
                | GraphState::Slashed { .. }
                | GraphState::Aborted { .. }
        )
    }

    fn is_pre_assignment_state(state: &GraphState) -> bool {
        matches!(
            state,
            GraphState::Created { .. }
                | GraphState::GraphGenerated { .. }
                | GraphState::AdaptorsVerified { .. }
                | GraphState::NoncesCollected { .. }
                | GraphState::GraphSigned { .. }
        )
    }

    #[test]
    fn test_deposit_request_taken_back_aborts_pre_assignment_states() {
        let cfg = test_graph_sm_cfg();
        let takeback_txid = generate_txid();
        let mut states = vec![GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        }];
        states.extend(pre_signing_states());

        for from_state in states {
            let expected_claim_txid = from_state.claim_txid();

            test_transition::<GraphSM, _, _, _, _, _, _, _>(
                crate::graph::tests::create_sm,
                get_state,
                cfg.clone(),
                GraphTransition {
                    from_state,
                    event: deposit_request_taken_back_event(TEST_DEPOSIT_IDX, takeback_txid),
                    expected_state: GraphState::Aborted {
                        claim_txid: expected_claim_txid,
                        reason: AbortReason::DepositRequestTakenBack {
                            spending_txid: takeback_txid,
                        },
                    },
                    expected_duties: vec![],
                    expected_signals: vec![],
                },
            );
        }
    }

    #[test]
    fn test_duplicate_deposit_request_taken_back_is_rejected() {
        let cfg = test_graph_sm_cfg();
        let takeback_txid = generate_txid();
        let from_state = GraphState::Aborted {
            claim_txid: None,
            reason: AbortReason::DepositRequestTakenBack {
                spending_txid: takeback_txid,
            },
        };
        let mut sm = crate::graph::tests::create_sm(from_state.clone());

        let result = sm.process_event(
            cfg,
            deposit_request_taken_back_event(TEST_DEPOSIT_IDX, takeback_txid),
        );

        assert!(
            matches!(result, Err(GSMError::Duplicate { .. })),
            "expected duplicate deposit request takeback, got {result:?}"
        );
        assert_eq!(
            sm.state(),
            &from_state,
            "duplicate deposit request takeback must not mutate state"
        );
    }

    #[test]
    fn test_deposit_request_taken_back_after_pre_assignment_is_invalid() {
        let cfg = test_graph_sm_cfg();
        let takeback_txid = generate_txid();

        for initial_state in all_state_variants()
            .into_iter()
            .filter(|state| !is_pre_assignment_state(state))
        {
            let state_name = initial_state.to_string();
            let mut sm = crate::graph::tests::create_sm(initial_state.clone());

            let result = sm.process_event(
                cfg.clone(),
                deposit_request_taken_back_event(TEST_DEPOSIT_IDX, takeback_txid),
            );

            assert!(
                matches!(
                    &result,
                    Err(GSMError::InvalidEvent {
                        reason: Some(reason),
                        ..
                    }) if reason.contains("requires explicit reorg recovery")
                ),
                "expected deposit request takeback to be invalid in {state_name}, got {result:?}"
            );
            assert_eq!(
                sm.state(),
                &initial_state,
                "invalid deposit request takeback must not mutate {state_name}"
            );
        }
    }

    #[test]
    fn test_deposit_request_taken_back_for_different_deposit_is_invalid() {
        let cfg = test_graph_sm_cfg();
        let from_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };
        let mut sm = crate::graph::tests::create_sm(from_state.clone());

        let result = sm.process_event(
            cfg,
            deposit_request_taken_back_event(TEST_DEPOSIT_IDX + 1, generate_txid()),
        );

        assert!(
            matches!(
                &result,
                Err(GSMError::InvalidEvent {
                    reason: Some(reason),
                    ..
                }) if reason.contains("different deposit")
            ),
            "expected misrouted deposit request takeback to be invalid, got {result:?}"
        );
        assert_eq!(
            sm.state(),
            &from_state,
            "invalid deposit request takeback must not mutate state"
        );
    }

    #[test]
    fn test_coop_payout_failed_from_fulfilled_pov_emits_publish_claim() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let fulfillment_txid = generate_txid();

        // Generate expected claim tx using the same config and context
        let game_graph = generate_game_graph(&cfg, &ctx, &test_deposit_params());

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            crate::graph::tests::create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: fulfilled_state(TEST_POV_IDX, fulfillment_txid),
                event: coop_payout_failed_event(),
                expected_state: GraphState::Fulfilled {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    graph_data: test_deposit_params(),
                    graph_summary: test_graph_summary(),
                    coop_payout_failed: true,
                    assignee: TEST_POV_IDX,
                    signatures: Default::default(),
                    fulfillment_txid,
                    fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
                    stake_spent: None,
                },
                expected_duties: vec![GraphDuty::PublishClaim {
                    claim_tx: game_graph.claim,
                }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn test_coop_payout_failed_from_fulfilled_nonpov_no_duties() {
        let cfg = test_graph_sm_cfg();
        let fulfillment_txid = generate_txid();

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: fulfilled_state(TEST_POV_IDX, fulfillment_txid),
                event: coop_payout_failed_event(),
                expected_state: GraphState::Fulfilled {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    graph_data: test_deposit_params(),
                    graph_summary: test_graph_summary(),
                    coop_payout_failed: true,
                    assignee: TEST_POV_IDX,
                    signatures: Default::default(),
                    fulfillment_txid,
                    fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
                    stake_spent: None,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn test_stale_coop_payout_failed_after_fulfilled_is_rejected() {
        let cfg = test_graph_sm_cfg();

        for initial_state in all_state_variants()
            .into_iter()
            .filter(is_after_fulfilled_state)
        {
            let state_name = initial_state.to_string();
            let mut sm = crate::graph::tests::create_sm(initial_state.clone());

            let result = sm.process_event(cfg.clone(), coop_payout_failed_event());

            assert!(
                matches!(
                    &result,
                    Err(GSMError::Rejected { reason, .. })
                        if reason.contains("stale cooperative payout failure")
                ),
                "expected stale cooperative payout failure to be rejected in {state_name}, got {result:?}"
            );
            assert_eq!(
                sm.state(),
                &initial_state,
                "rejected stale cooperative payout failure must not mutate {state_name}"
            );
        }
    }

    #[test]
    fn test_coop_payout_failed_from_non_fulfilled_states() {
        let non_fulfilled_states: Vec<GraphState> = all_state_variants()
            .into_iter()
            .filter(|s| !matches!(s, GraphState::Fulfilled { .. }))
            .filter(|s| !is_after_fulfilled_state(s))
            .collect();

        for state in non_fulfilled_states {
            test_graph_invalid_transition(GraphInvalidTransition {
                from_state: state,
                event: coop_payout_failed_event(),
                expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
            });
        }
    }
}
