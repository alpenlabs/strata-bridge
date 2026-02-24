//! Unit tests for processing of the bridge proof timeout.

use bitcoin::{Txid, hashes::Hash};

use crate::graph::{
    errors::GSMError,
    events::{BridgeProofTimeoutConfirmedEvent, GraphEvent},
    state::GraphState,
    tests::{
        GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT,
        mock_states::{
            TEST_GRAPH_SUMMARY, all_state_variants, bridge_proof_timedout_state, contested_state,
        },
        test_deposit_params, test_graph_invalid_transition, test_graph_transition,
    },
};

#[test]
fn event_accepted() {
    test_graph_transition(GraphTransition {
        from_state: contested_state(),
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
            bridge_proof_timeout_block_height: u64::MAX,
        }),
        expected_state: GraphState::BridgeProofTimedout {
            last_block_height: u64::MAX,
            graph_data: test_deposit_params(),
            signatures: vec![],
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_slash_txid: TEST_GRAPH_SUMMARY.slash,
            claim_txid: TEST_GRAPH_SUMMARY.claim,
            graph_summary: TEST_GRAPH_SUMMARY.clone(),
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn event_duplicate() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: bridge_proof_timedout_state(),
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
            bridge_proof_timeout_block_height: u64::MAX,
        }),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn event_rejected_old_height() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: contested_state(),
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
            bridge_proof_timeout_block_height: 0,
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_invalid_txid() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: contested_state(),
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: Txid::all_zeros(),
            bridge_proof_timeout_block_height: 0,
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
            event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
                bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
                bridge_proof_timeout_block_height: u64::MAX,
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

/// Returns `true` if the state is valid for [`GraphEvent::BridgeProofTimeoutConfirmed`].
fn state_is_valid(state: &GraphState) -> bool {
    matches!(
        state,
        GraphState::Contested { .. } | GraphState::BridgeProofTimedout { .. }
    )
}
