//! Unit Tests for process_assignment
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::graph::{
        errors::GSMError,
        events::{GraphEvent, WithdrawalAssignedEvent},
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, TEST_NONPOV_IDX, TEST_POV_IDX,
            mock_states::{
                acked_state, all_nackd_state, assigned_state, bridge_proof_posted_state,
                bridge_proof_timedout_state, claimed_state, contested_state,
                counter_proof_posted_state, fulfilled_state, graph_signed_state,
                pre_signing_states, terminal_states, test_nonce_context,
            },
            random_p2tr_desc, test_graph_invalid_transition, test_graph_transition,
            test_recipient_desc,
        },
    };

    /// A block height used for reassignment deadlines.
    const REASSIGNMENT_DEADLINE: u64 = 200;
    const UPDATED_REASSIGNMENT_DEADLINE: u64 = REASSIGNMENT_DEADLINE + 50;

    #[test]
    fn test_assignment_from_graph_signed() {
        let (_, _, nonce_ctx) = test_nonce_context();
        let desc = random_p2tr_desc();

        test_graph_transition(GraphTransition {
            from_state: graph_signed_state(&nonce_ctx),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            }),
            expected_state: assigned_state(&nonce_ctx, TEST_POV_IDX, REASSIGNMENT_DEADLINE, desc),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_assignment_from_graph_signed_rejected_for_non_pov_operator() {
        let (_, _, nonce_ctx) = test_nonce_context();
        let desc = random_p2tr_desc();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: graph_signed_state(&nonce_ctx),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_NONPOV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_reassignment_same_assignee_different_deadline() {
        let (_, _, nonce_ctx) = test_nonce_context();
        let desc = random_p2tr_desc();

        test_graph_transition(GraphTransition {
            from_state: assigned_state(
                &nonce_ctx,
                TEST_POV_IDX,
                REASSIGNMENT_DEADLINE,
                desc.clone(),
            ),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: UPDATED_REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            }),
            expected_state: assigned_state(
                &nonce_ctx,
                TEST_POV_IDX,
                UPDATED_REASSIGNMENT_DEADLINE,
                desc,
            ),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_reassignment_rejected_when_recipient_changes() {
        let (_, _, nonce_ctx) = test_nonce_context();
        let old_desc = random_p2tr_desc();
        let new_desc = random_p2tr_desc();
        assert_ne!(old_desc, new_desc, "descriptors must differ");

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: assigned_state(&nonce_ctx, TEST_POV_IDX, REASSIGNMENT_DEADLINE, old_desc),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: UPDATED_REASSIGNMENT_DEADLINE,
                recipient_desc: new_desc,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_reassignment_different_assignee_reverts_to_graph_signed() {
        let (_, _, nonce_ctx) = test_nonce_context();
        let desc = test_recipient_desc(1);

        test_graph_transition(GraphTransition {
            from_state: assigned_state(
                &nonce_ctx,
                TEST_NONPOV_IDX,
                REASSIGNMENT_DEADLINE,
                desc.clone(),
            ),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: UPDATED_REASSIGNMENT_DEADLINE,
                recipient_desc: desc,
            }),
            expected_state: graph_signed_state(&nonce_ctx),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_reassignment_rejected_when_invalid_deadline() {
        let (_, _, nonce_ctx) = test_nonce_context();
        let desc = random_p2tr_desc();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: assigned_state(
                &nonce_ctx,
                TEST_POV_IDX,
                REASSIGNMENT_DEADLINE,
                desc.clone(),
            ),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE - 50,
                recipient_desc: desc,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_reassignment_different_assignee_rejected_when_invalid_deadline() {
        let (_, _, nonce_ctx) = test_nonce_context();
        let desc = test_recipient_desc(1);

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: assigned_state(
                &nonce_ctx,
                TEST_NONPOV_IDX,
                REASSIGNMENT_DEADLINE,
                desc.clone(),
            ),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE - 50,
                recipient_desc: desc,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_assignment_invalid_from_other_states() {
        let desc = random_p2tr_desc();

        let mut invalid_states: Vec<_> = pre_signing_states()
            .into_iter()
            .filter(|s| !matches!(s, GraphState::GraphSigned { .. }))
            .collect();
        invalid_states.extend(terminal_states());

        for state in invalid_states {
            test_graph_invalid_transition(GraphInvalidTransition {
                from_state: state,
                event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                    assignee: TEST_POV_IDX,
                    deadline: REASSIGNMENT_DEADLINE,
                    recipient_desc: desc.clone(),
                }),
                expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
            });
        }
    }

    #[test]
    fn test_assignment_duplicate_from_post_assignment_states() {
        let desc = random_p2tr_desc();

        let post_assignment_states = vec![
            fulfilled_state(TEST_POV_IDX, generate_txid()),
            claimed_state(100, generate_txid(), vec![]),
            contested_state(),
            bridge_proof_posted_state(),
            bridge_proof_timedout_state(),
            counter_proof_posted_state(),
            all_nackd_state(),
            acked_state(),
        ];

        for state in post_assignment_states {
            test_graph_invalid_transition(GraphInvalidTransition {
                from_state: state,
                event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                    assignee: TEST_POV_IDX,
                    deadline: REASSIGNMENT_DEADLINE,
                    recipient_desc: desc.clone(),
                }),
                expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
            });
        }
    }
}
