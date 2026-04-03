//! Unit tests for processing of counterproof ACK confirmation.

use bitcoin::{Txid, hashes::Hash};

use crate::{
    graph::{
        errors::GSMError,
        events::{CounterProofAckConfirmedEvent, GraphEvent},
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,
            create_nonpov_sm, get_state,
            mock_states::{
                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, acked_state, all_state_variants,
                counter_proof_posted_state,
            },
            test_graph_invalid_transition, test_graph_sm_cfg, test_graph_transition,
        },
    },
    testing::test_transition,
};

const ACK_BLOCK_HEIGHT: u64 = u64::MAX;

#[test]
fn event_accepted() {
    test_graph_transition(GraphTransition {
        from_state: counter_proof_posted_state(),
        event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
            counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
            counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
            counterprover_idx: TEST_NONPOV_IDX,
        }),
        expected_state: GraphState::Acked {
            last_block_height: ACK_BLOCK_HEIGHT,
            graph_data: crate::graph::tests::test_deposit_params(),
            signatures: Default::default(),
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_slash_txid: TEST_GRAPH_SUMMARY.slash,
            claim_txid: TEST_GRAPH_SUMMARY.claim,
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn event_accepted_nonpov() {
    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        GraphTransition {
            from_state: counter_proof_posted_state(),
            event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
                counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
                counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
                counterprover_idx: TEST_NONPOV_IDX,
            }),
            expected_state: GraphState::Acked {
                last_block_height: ACK_BLOCK_HEIGHT,
                graph_data: crate::graph::tests::test_deposit_params(),
                signatures: Default::default(),
                contest_block_height: LATER_BLOCK_HEIGHT,
                expected_slash_txid: TEST_GRAPH_SUMMARY.slash,
                claim_txid: TEST_GRAPH_SUMMARY.claim,
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn event_duplicate() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: acked_state(),
        event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
            counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
            counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
            counterprover_idx: TEST_NONPOV_IDX,
        }),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn event_rejected_invalid_txid() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_state(),
        event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
            counterproof_ack_txid: Txid::all_zeros(),
            counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
            counterprover_idx: TEST_NONPOV_IDX,
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_invalid_operator_idx() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_state(),
        event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
            counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
            counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
            counterprover_idx: u32::MAX,
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_invalid() {
    for from_state in all_state_variants()
        .into_iter()
        .filter(|state| !state_is_valid(state))
    {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state,
            event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
                counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
                counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
                counterprover_idx: TEST_NONPOV_IDX,
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

fn state_is_valid(state: &GraphState) -> bool {
    matches!(
        state,
        GraphState::CounterProofPosted { .. } | GraphState::Acked { .. }
    )
}
