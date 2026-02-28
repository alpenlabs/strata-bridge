//! Unit Tests for process_claim

use strata_bridge_test_utils::bitcoin::generate_txid;

use crate::graph::{
    errors::GSMError,
    events::{ClaimConfirmedEvent, GraphEvent},
    state::GraphState,
    tests::{
        FULFILLMENT_BLOCK_HEIGHT, GraphInvalidTransition, GraphTransition, INITIAL_BLOCK_HEIGHT,
        mock_states::fulfilled_state, test_deposit_params, test_graph_invalid_transition,
        test_graph_summary, test_graph_transition,
    },
};

/// Block height at which the claim transaction was confirmed.
const CLAIM_BLOCK_HEIGHT: u64 = 160;

/// Builds a mock `Claimed` state with fulfillment data.
fn claimed_state(fulfillment_txid: bitcoin::Txid, claim_block_height: u64) -> GraphState {
    GraphState::Claimed {
        last_block_height: INITIAL_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: test_graph_summary(),
        signatures: Default::default(),
        fulfillment_txid: Some(fulfillment_txid),
        fulfillment_block_height: Some(FULFILLMENT_BLOCK_HEIGHT),
        claim_block_height,
    }
}

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
        expected_state: claimed_state(fulfillment_txid, CLAIM_BLOCK_HEIGHT),
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn test_claim_rejected_invalid_txid() {
    let fulfillment_txid = generate_txid();
    let wrong_claim_txid = test_graph_summary().slash;

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: fulfilled_state(fulfillment_txid),
        event: GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
            claim_txid: wrong_claim_txid,
            claim_block_height: CLAIM_BLOCK_HEIGHT,
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn test_duplicate_claim() {
    let fulfillment_txid = generate_txid();

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: claimed_state(fulfillment_txid, CLAIM_BLOCK_HEIGHT),
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
