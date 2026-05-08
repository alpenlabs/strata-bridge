//! Unit tests for processing of the bridge proof timeout.

use bitcoin::{Txid, hashes::Hash};

use crate::graph::{
    errors::GSMError,
    events::{BridgeProofTimeoutConfirmedEvent, GraphEvent},
    state::{AbortReason, GraphState},
    tests::{
        GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT,
        mock_states::{
            TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_state_variants,
            bridge_proof_timedout_state, contested_state,
            counter_proof_posted_without_refuted_proof_state,
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
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
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
fn event_accepted_from_counterproof_posted_without_proof() {
    test_graph_transition(GraphTransition {
        from_state: counter_proof_posted_without_refuted_proof_state(),
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
            bridge_proof_timeout_block_height: u64::MAX,
        }),
        expected_state: GraphState::BridgeProofTimedout {
            last_block_height: u64::MAX,
            graph_data: test_deposit_params(),
            signatures: vec![],
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
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
fn event_rejected_invalid_txid() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: contested_state(),
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: Txid::all_zeros(),
            bridge_proof_timeout_block_height: 0,
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_without_refuted_proof_state(),
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
        GraphState::Contested { .. }
            | GraphState::BridgeProofTimedout { .. }
            | GraphState::CounterProofPosted {
                refuted_bridge_proof: None,
                ..
            }
    )
}

/// Pre-recording a stake spend on `Contested` causes a valid timeout event
/// to abort instead of entering `BridgeProofTimedout` — the only remaining
/// path from that state is slash, which is impossible once the stake
/// outpoint is gone.
#[test]
fn aborts_when_stake_already_spent_in_contested() {
    let stake_spending_txid = Txid::from_byte_array([0xab; 32]);
    let mut from_state = contested_state();
    let claim_txid = from_state
        .claim_txid()
        .expect("Contested state should have claim txid");
    assert!(from_state.set_stake_spent(stake_spending_txid));

    test_graph_transition(GraphTransition {
        from_state,
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
            bridge_proof_timeout_block_height: u64::MAX,
        }),
        expected_state: GraphState::Aborted {
            claim_txid,
            reason: AbortReason::StakeSpent {
                spending_txid: stake_spending_txid,
            },
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

/// Same proactive abort applies when transitioning from
/// `CounterProofPosted` (with no refuted proof) into `BridgeProofTimedout`.
#[test]
fn aborts_when_stake_already_spent_in_counterproof_posted() {
    let stake_spending_txid = Txid::from_byte_array([0xab; 32]);
    let mut from_state = counter_proof_posted_without_refuted_proof_state();
    let claim_txid = from_state
        .claim_txid()
        .expect("CounterProofPosted without refuted proof should have claim txid");
    assert!(from_state.set_stake_spent(stake_spending_txid));

    test_graph_transition(GraphTransition {
        from_state,
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
            bridge_proof_timeout_block_height: u64::MAX,
        }),
        expected_state: GraphState::Aborted {
            claim_txid,
            reason: AbortReason::StakeSpent {
                spending_txid: stake_spending_txid,
            },
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

/// A pre-recorded `payout_connector_spent` does *not* trigger proactive
/// abort — slashing remains possible from `BridgeProofTimedout` regardless
/// of connector status.
#[test]
fn payout_connector_spent_alone_does_not_abort() {
    let connector_spending_txid = Txid::from_byte_array([0xcd; 32]);
    let mut from_state = contested_state();
    assert!(from_state.set_payout_connector_spent(connector_spending_txid));

    test_graph_transition(GraphTransition {
        from_state,
        event: GraphEvent::BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent {
            bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
            bridge_proof_timeout_block_height: u64::MAX,
        }),
        expected_state: GraphState::BridgeProofTimedout {
            last_block_height: u64::MAX,
            graph_data: test_deposit_params(),
            signatures: vec![],
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_slash_txid: TEST_GRAPH_SUMMARY.slash,
            claim_txid: TEST_GRAPH_SUMMARY.claim,
            graph_summary: TEST_GRAPH_SUMMARY.clone(),
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}
