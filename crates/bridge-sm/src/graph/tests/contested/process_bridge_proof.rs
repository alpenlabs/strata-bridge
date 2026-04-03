//! Unit tests for processing of the bridge proof confirmation.

use bitcoin::{Txid, hashes::Hash};

use crate::graph::{
    errors::GSMError,
    events::{BridgeProofConfirmedEvent, GraphEvent},
    state::GraphState,
    tests::{
        GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, dummy_proof_receipt,
        mock_states::{
            TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_state_variants,
            bridge_proof_posted_state, contested_state,
        },
        test_deposit_params, test_graph_invalid_transition, test_graph_transition,
    },
};

/// Block height at which the bridge proof transaction was confirmed.
const BRIDGE_PROOF_BLOCK_HEIGHT: u64 = u64::MAX;

fn bridge_proof_event() -> BridgeProofConfirmedEvent {
    BridgeProofConfirmedEvent {
        bridge_proof_txid: Txid::from_byte_array([0xAB; 32]),
        bridge_proof_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
        proof: dummy_proof_receipt(),
    }
}

#[test]
fn event_accepted() {
    let event = bridge_proof_event();

    test_graph_transition(GraphTransition {
        from_state: contested_state(),
        event: GraphEvent::BridgeProofConfirmed(event.clone()),
        expected_state: GraphState::BridgeProofPosted {
            last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: TEST_GRAPH_SUMMARY.clone(),
            signatures: vec![],
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            bridge_proof_txid: event.bridge_proof_txid,
            bridge_proof_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
            proof: dummy_proof_receipt(),
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn event_duplicate() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: bridge_proof_posted_state(),
        event: GraphEvent::BridgeProofConfirmed(bridge_proof_event()),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
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
            event: GraphEvent::BridgeProofConfirmed(bridge_proof_event()),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

/// Returns `true` if the state is valid for [`GraphEvent::BridgeProofConfirmed`].
fn state_is_valid(state: &GraphState) -> bool {
    matches!(
        state,
        GraphState::Contested { .. } | GraphState::BridgeProofPosted { .. }
    )
}
