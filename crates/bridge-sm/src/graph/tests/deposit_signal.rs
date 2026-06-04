//! Unit Tests for process_deposit_signal (CooperativePayoutFailed from Deposit SM)
#[cfg(test)]
mod tests {
    use strata_bridge_primitives::types::GraphIdx;
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::GraphEvent,
            machine::{GraphSM, generate_game_graph},
            state::GraphState,
            tests::{
                FULFILLMENT_BLOCK_HEIGHT, GraphInvalidTransition, GraphTransition,
                INITIAL_BLOCK_HEIGHT, TEST_POV_IDX, create_nonpov_sm, get_state,
                mock_states::{all_state_variants, fulfilled_state},
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
