//! Unit Tests for process_payout_connector_spent (abort condition)

use strata_bridge_test_utils::bitcoin::generate_txid;

use crate::graph::{
    errors::GSMError,
    events::{GraphEvent, PayoutConnectorSpentEvent},
    state::GraphState,
    tests::{
        GraphInvalidTransition, GraphTransition,
        mock_states::{all_state_variants, payout_connector_spent_states},
        test_graph_invalid_transition, test_graph_transition,
    },
};

fn payout_connector_spent_event() -> PayoutConnectorSpentEvent {
    PayoutConnectorSpentEvent {
        spending_txid: generate_txid(),
    }
}

#[test]
fn event_accepted() {
    for from_state in payout_connector_spent_states() {
        let event = payout_connector_spent_event();

        test_graph_transition(GraphTransition {
            from_state,
            event: GraphEvent::PayoutConnectorSpent(event.clone()),
            expected_state: GraphState::Aborted {
                payout_connector_spend_txid: event.spending_txid,
                reason: "Payout connector spent".to_string(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }
}

#[test]
fn event_duplicate() {
    let spending_txid = generate_txid();

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: GraphState::Aborted {
            payout_connector_spend_txid: spending_txid,
            reason: "Payout connector spent".to_string(),
        },
        event: GraphEvent::PayoutConnectorSpent(PayoutConnectorSpentEvent { spending_txid }),
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
            event: GraphEvent::PayoutConnectorSpent(payout_connector_spent_event()),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

/// Returns `true` if the state is valid for [`GraphEvent::PayoutConnectorSpent`].
fn state_is_valid(state: &GraphState) -> bool {
    matches!(
        state,
        GraphState::Claimed { .. }
            | GraphState::Contested { .. }
            | GraphState::BridgeProofPosted { .. }
            | GraphState::BridgeProofTimedout { .. }
            | GraphState::CounterProofPosted { .. }
            | GraphState::Aborted { .. }
    )
}
