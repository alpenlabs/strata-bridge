//! Unit Tests for process_assignment
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::graph::{
        errors::GSMError,
        events::{GraphEvent, WithdrawalAssignedEvent},
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, INITIAL_BLOCK_HEIGHT, TEST_NONPOV_IDX,
            TEST_POV_IDX, random_p2tr_desc, test_deposit_params, test_graph_invalid_transition,
            test_graph_summary, test_graph_transition, test_recipient_desc,
        },
    };

    /// A block height used for reassignment deadlines.
    const REASSIGNMENT_DEADLINE: u64 = 200;
    const UPDATED_REASSIGNMENT_DEADLINE: u64 = REASSIGNMENT_DEADLINE + 50;

    /// Builds a mock `GraphSigned` state.
    fn graph_signed_state() -> GraphState {
        GraphState::GraphSigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
        }
    }

    /// Builds a mock `Assigned` state with the given assignment fields.
    fn assigned_state(
        assignee: u32,
        deadline: u64,
        recipient_desc: bitcoin_bosd::Descriptor,
    ) -> GraphState {
        GraphState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            assignee,
            deadline,
            recipient_desc,
        }
    }

    #[test]
    fn test_assignment_from_graph_signed() {
        let desc = random_p2tr_desc();

        test_graph_transition(GraphTransition {
            from_state: graph_signed_state(),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            }),
            expected_state: assigned_state(TEST_POV_IDX, REASSIGNMENT_DEADLINE, desc),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_assignment_from_graph_signed_rejected_for_non_pov_operator() {
        let desc = random_p2tr_desc();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: graph_signed_state(),
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
        let desc = random_p2tr_desc();

        test_graph_transition(GraphTransition {
            from_state: assigned_state(TEST_POV_IDX, REASSIGNMENT_DEADLINE, desc.clone()),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: UPDATED_REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            }),
            expected_state: assigned_state(TEST_POV_IDX, UPDATED_REASSIGNMENT_DEADLINE, desc),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_reassignment_rejected_when_recipient_changes() {
        let old_desc = random_p2tr_desc();
        let new_desc = random_p2tr_desc();
        assert_ne!(old_desc, new_desc, "descriptors must differ");

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: assigned_state(TEST_POV_IDX, REASSIGNMENT_DEADLINE, old_desc),
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
        let desc = test_recipient_desc(1);

        test_graph_transition(GraphTransition {
            from_state: assigned_state(TEST_NONPOV_IDX, REASSIGNMENT_DEADLINE, desc.clone()),
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: UPDATED_REASSIGNMENT_DEADLINE,
                recipient_desc: desc,
            }),
            expected_state: graph_signed_state(),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_reassignment_rejected_when_invalid_deadline() {
        let desc = random_p2tr_desc();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: assigned_state(TEST_POV_IDX, REASSIGNMENT_DEADLINE, desc.clone()),
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
        let desc = test_recipient_desc(1);

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: assigned_state(TEST_NONPOV_IDX, REASSIGNMENT_DEADLINE, desc.clone()),
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

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::Withdrawn {
                payout_txid: generate_txid(),
            },
            event: GraphEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc,
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
