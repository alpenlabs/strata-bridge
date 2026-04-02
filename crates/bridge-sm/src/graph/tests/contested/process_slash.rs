//! Unit tests for processing of slash confirmation.

use bitcoin::{Txid, hashes::Hash};

use crate::graph::{
    errors::GSMError,
    events::{GraphEvent, SlashConfirmedEvent},
    state::GraphState,
    tests::{
        GraphInvalidTransition, GraphTransition,
        mock_states::{
            TEST_GRAPH_SUMMARY, acked_state, all_nackd_state, all_state_variants,
            bridge_proof_timedout_state,
        },
        test_graph_invalid_transition, test_graph_transition,
    },
};

#[test]
fn event_accepted_from_bridge_proof_timedout() {
    test_graph_transition(GraphTransition {
        from_state: bridge_proof_timedout_state(),
        event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        }),
        expected_state: GraphState::Slashed {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn event_accepted_from_acked() {
    test_graph_transition(GraphTransition {
        from_state: acked_state(),
        event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        }),
        expected_state: GraphState::Slashed {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn event_accepted_from_all_nackd() {
    test_graph_transition(GraphTransition {
        from_state: all_nackd_state(),
        event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        }),
        expected_state: GraphState::Slashed {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn event_duplicate() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: GraphState::Slashed {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        },
        event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
            slash_txid: TEST_GRAPH_SUMMARY.slash,
        }),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn event_rejected_invalid_txid_bridge_proof_timedout() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: bridge_proof_timedout_state(),
        event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
            slash_txid: Txid::all_zeros(),
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_invalid_txid_acked() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: acked_state(),
        event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
            slash_txid: Txid::all_zeros(),
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_invalid_txid_all_nackd() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: all_nackd_state(),
        event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
            slash_txid: Txid::all_zeros(),
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
            event: GraphEvent::SlashConfirmed(SlashConfirmedEvent {
                slash_txid: TEST_GRAPH_SUMMARY.slash,
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

fn state_is_valid(state: &GraphState) -> bool {
    matches!(
        state,
        GraphState::BridgeProofTimedout { .. }
            | GraphState::Acked { .. }
            | GraphState::AllNackd { .. }
            | GraphState::Slashed { .. }
    )
}
