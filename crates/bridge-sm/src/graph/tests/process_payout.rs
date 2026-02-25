//! Unit Tests for process_payout (from Claimed state)
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::graph::{
        errors::GSMError,
        events::{GraphEvent, PayoutConfirmedEvent},
        state::GraphState,
        tests::{
            ASSIGNMENT_DEADLINE, CLAIM_BLOCK_HEIGHT, GraphInvalidTransition, GraphTransition,
            INITIAL_BLOCK_HEIGHT, TEST_POV_IDX,
            mock_states::{assigned_state, claimed_state},
            test_deposit_params, test_graph_invalid_transition, test_graph_summary,
            test_graph_transition, test_recipient_desc,
        },
    };

    #[test]
    fn test_payout_from_claimed() {
        let graph_summary = test_graph_summary();
        let payout_txid = graph_summary.uncontested_payout;

        test_graph_transition(GraphTransition {
            from_state: GraphState::Claimed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary,
                signatures: Default::default(),
                fulfillment_txid: Some(generate_txid()),
                fulfillment_block_height: Some(INITIAL_BLOCK_HEIGHT),
                claim_block_height: CLAIM_BLOCK_HEIGHT,
            },
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent { payout_txid }),
            expected_state: GraphState::Withdrawn { payout_txid },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_payout_rejected_invalid_txid() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: claimed_state(INITIAL_BLOCK_HEIGHT, generate_txid(), Default::default()),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_duplicate_payout() {
        let payout_txid = generate_txid();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: GraphState::Withdrawn { payout_txid },
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent { payout_txid }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_payout_from_invalid_state() {
        let state = assigned_state(TEST_POV_IDX, ASSIGNMENT_DEADLINE, test_recipient_desc(1));

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
