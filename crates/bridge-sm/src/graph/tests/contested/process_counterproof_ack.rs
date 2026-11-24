//! Unit tests for processing of counterproof ACK confirmation.

use bitcoin::{Txid, hashes::Hash};

use crate::{
    graph::{
        errors::GSMError,
        events::{CounterProofAckConfirmedEvent, GraphEvent},
        state::{AbortReason, CounterproofData, GraphState, PayoutBlockData},
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,
            create_nonpov_sm, get_state,
            mock_states::{
                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, acked_state, all_state_variants,
                counter_proof_posted_state as mock_counter_proof_posted_state,
            },
            test_completed_signatures, test_deposit_params, test_graph_invalid_transition,
            test_graph_transition,
        },
    },
    testing::test_transition,
};

const ACK_BLOCK_HEIGHT: u64 = LATER_BLOCK_HEIGHT + 100;

fn counter_proof_posted_state() -> GraphState {
    let mut state = mock_counter_proof_posted_state();
    let GraphState::CounterProofPosted {
        last_block_height,
        refuted_bridge_proof,
        counterproofs_and_confs,
        ..
    } = &mut state
    else {
        unreachable!();
    };
    *last_block_height = LATER_BLOCK_HEIGHT + 1;
    *refuted_bridge_proof = None;
    counterproofs_and_confs.insert(
        TEST_NONPOV_IDX,
        CounterproofData {
            txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof,
            conf_height: LATER_BLOCK_HEIGHT + 1,
            completed_signatures: test_completed_signatures(),
        },
    );
    state
}

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
            graph_data: test_deposit_params(),
            signatures: Default::default(),
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_slash_txid: TEST_GRAPH_SUMMARY.slash,
            claim_txid: TEST_GRAPH_SUMMARY.claim,
            contest_txid: Some(TEST_GRAPH_SUMMARY.contest),
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            payout_block_data: Default::default(),
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
        (),
        GraphTransition {
            from_state: counter_proof_posted_state(),
            event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
                counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
                counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
                counterprover_idx: TEST_NONPOV_IDX,
            }),
            expected_state: GraphState::Acked {
                last_block_height: ACK_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                signatures: Default::default(),
                contest_block_height: LATER_BLOCK_HEIGHT,
                expected_slash_txid: TEST_GRAPH_SUMMARY.slash,
                claim_txid: TEST_GRAPH_SUMMARY.claim,
                contest_txid: Some(TEST_GRAPH_SUMMARY.contest),
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                payout_block_data: Default::default(),
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
        expected_error: |e| matches!(e, GSMError::Rejected { reason, .. } if reason.contains("not in operator table")),
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

/// Pre-recording a stake spend on `CounterProofPosted` causes a valid ACK
/// event to abort instead of entering `Acked` — the only remaining path
/// from that state is slash, which is impossible once the stake outpoint
/// is gone.
#[test]
fn aborts_when_stake_already_spent() {
    let stake_spending_txid = Txid::from_byte_array([0xab; 32]);
    let mut from_state = counter_proof_posted_state();
    let claim_txid = from_state
        .claim_txid()
        .expect("CounterProofPosted state should have claim_txid");
    assert!(from_state.set_stake_spent(stake_spending_txid));

    test_graph_transition(GraphTransition {
        from_state,
        event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
            counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
            counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
            counterprover_idx: TEST_NONPOV_IDX,
        }),
        expected_state: GraphState::Aborted {
            claim_txid: Some(claim_txid),
            reason: AbortReason::StakeSpent {
                spending_txid: stake_spending_txid,
            },
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

/// A pre-recorded `payout_connector_spent` does *not* trigger proactive
/// abort — slashing remains possible from `Acked` regardless of connector
/// status.
#[test]
fn payout_connector_spent_alone_does_not_abort() {
    let connector_spending_txid = Txid::from_byte_array([0xcd; 32]);
    let mut from_state = counter_proof_posted_state();
    assert!(from_state.set_payout_connector_spent(connector_spending_txid));
    let payout_block_data = PayoutBlockData {
        admin_block_txid: Some(connector_spending_txid),
        unstaking_block_txid: None,
    };
    from_state.set_payout_block_data(payout_block_data);

    test_graph_transition(GraphTransition {
        from_state,
        event: GraphEvent::CounterProofAckConfirmed(CounterProofAckConfirmedEvent {
            counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
            counterproof_ack_block_height: ACK_BLOCK_HEIGHT,
            counterprover_idx: TEST_NONPOV_IDX,
        }),
        expected_state: GraphState::Acked {
            last_block_height: ACK_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            signatures: Default::default(),
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_slash_txid: TEST_GRAPH_SUMMARY.slash,
            claim_txid: TEST_GRAPH_SUMMARY.claim,
            contest_txid: Some(TEST_GRAPH_SUMMARY.contest),
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            payout_block_data,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}
