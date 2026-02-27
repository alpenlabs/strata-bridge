//! Unit Tests for process_claim
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{ClaimConfirmedEvent, GraphEvent},
            machine::{GraphSM, generate_game_graph},
            state::GraphState,
            tests::{
                ASSIGNMENT_DEADLINE, FULFILLMENT_BLOCK_HEIGHT, GraphInvalidTransition,
                GraphTransition, INITIAL_BLOCK_HEIGHT, TEST_POV_IDX, create_nonpov_sm, create_sm,
                get_state, mock_game_signatures,
                mock_states::{assigned_state, claimed_state, fulfilled_state, graph_signed_state},
                test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
                test_graph_summary, test_graph_transition, test_recipient_desc,
            },
        },
        state_machine::StateMachine,
        testing::test_transition,
    };

    /// Block height at which the claim transaction was confirmed.
    const CLAIM_BLOCK_HEIGHT: u64 = 160;

    #[test]
    fn test_claim_from_fulfilled() {
        let fulfillment_txid = generate_txid();
        let claim_txid = test_graph_summary().claim;

        test_graph_transition(GraphTransition {
            from_state: fulfilled_state(fulfillment_txid),
            event: GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                claim_txid,
                claim_block_height: CLAIM_BLOCK_HEIGHT,
            }),
            expected_state: GraphState::Claimed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                signatures: Default::default(),
                fulfillment_txid: Some(fulfillment_txid),
                fulfillment_block_height: Some(FULFILLMENT_BLOCK_HEIGHT),
                claim_block_height: CLAIM_BLOCK_HEIGHT,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_faulty_claim_emits_contest_for_watchtower() {
        let cfg = test_graph_sm_cfg();

        // Build valid signatures from the non-PoV game graph
        let nonpov_ctx = create_nonpov_sm(graph_signed_state()).context.clone();
        let game_graph = generate_game_graph(&cfg, &nonpov_ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);

        let from_states = [
            GraphState::GraphSigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                signatures: signatures.clone(),
            },
            GraphState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                signatures: signatures.clone(),
                assignee: TEST_POV_IDX,
                deadline: ASSIGNMENT_DEADLINE,
                recipient_desc: test_recipient_desc(1),
            },
        ];

        for from_state in from_states {
            let mut sm = create_nonpov_sm(from_state);

            let result = sm
                .process_event(
                    cfg.clone(),
                    GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                        claim_txid: test_graph_summary().claim,
                        claim_block_height: CLAIM_BLOCK_HEIGHT,
                    }),
                )
                .expect("transition should succeed");

            assert!(
                matches!(
                    sm.state(),
                    GraphState::Claimed {
                        fulfillment_txid: None,
                        ..
                    }
                ),
                "Expected Claimed state without fulfillment"
            );
            assert_eq!(result.duties.len(), 1, "Expected exactly one duty");
            assert!(
                matches!(&result.duties[0], GraphDuty::PublishContest { .. }),
                "Expected PublishContest duty"
            );
        }
    }

    #[test]
    fn test_faulty_claim_no_duty_for_pov() {
        let from_states = [
            graph_signed_state(),
            assigned_state(TEST_POV_IDX, ASSIGNMENT_DEADLINE, test_recipient_desc(1)),
        ];

        for from_state in from_states {
            let cfg = test_graph_sm_cfg();

            let expected_state = GraphState::Claimed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                signatures: Default::default(),
                fulfillment_txid: None,
                fulfillment_block_height: None,
                claim_block_height: CLAIM_BLOCK_HEIGHT,
            };

            test_transition::<GraphSM, _, _, _, _, _, _, _>(
                create_sm,
                get_state,
                cfg,
                GraphTransition {
                    from_state,
                    event: GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                        claim_txid: test_graph_summary().claim,
                        claim_block_height: CLAIM_BLOCK_HEIGHT,
                    }),
                    expected_state,
                    expected_duties: vec![],
                    expected_signals: vec![],
                },
            );
        }
    }

    #[test]
    fn test_claim_rejected_invalid_txid() {
        let from_states = [
            fulfilled_state(generate_txid()),
            graph_signed_state(),
            assigned_state(TEST_POV_IDX, ASSIGNMENT_DEADLINE, test_recipient_desc(1)),
        ];

        for from_state in from_states {
            test_graph_invalid_transition(GraphInvalidTransition {
                from_state,
                event: GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                    claim_txid: test_graph_summary().slash,
                    claim_block_height: CLAIM_BLOCK_HEIGHT,
                }),
                expected_error: |e| matches!(e, GSMError::Rejected { .. }),
            });
        }
    }

    #[test]
    fn test_duplicate_claim() {
        let fulfillment_txid = generate_txid();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: claimed_state(INITIAL_BLOCK_HEIGHT, fulfillment_txid, Default::default()),
            event: GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                claim_txid: test_graph_summary().claim,
                claim_block_height: CLAIM_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_claim_invalid_from_other_states() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::Withdrawn {
                payout_txid: generate_txid(),
            },
            event: GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                claim_txid: test_graph_summary().claim,
                claim_block_height: CLAIM_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
