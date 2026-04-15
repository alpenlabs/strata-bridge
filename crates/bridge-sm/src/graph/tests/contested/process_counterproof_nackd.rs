//! Unit tests for processing of counterproof NACK confirmation.
//!
//! NOTE: The shared test fixture (`test_graph_summary`) has only one watchtower slot, so
//! a single NACK is enough to reach `AllNackd`.

use std::collections::BTreeMap;

use strata_bridge_test_utils::prelude::generate_txid;

use crate::{
    graph::{
        errors::GSMError,
        events::{CounterProofNackConfirmedEvent, GraphEvent},
        machine::GraphSM,
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,
            create_nonpov_sm, get_state,
            mock_states::{
                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_nackd_state, all_state_variants,
                counter_proof_posted_state, counter_proof_posted_state_with_counterproof,
            },
            test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
            test_graph_transition,
        },
    },
    testing::test_transition,
};

/// Creates a nack event for the given counterprover.
fn nack_event(counterprover_idx: u32) -> CounterProofNackConfirmedEvent {
    CounterProofNackConfirmedEvent {
        counterproof_nack_txid: generate_txid(),
        counterprover_idx,
    }
}

#[test]
fn event_accepted_transitions_to_all_nackd() {
    let event = nack_event(TEST_NONPOV_IDX);

    test_graph_transition(GraphTransition {
        from_state: counter_proof_posted_state_with_counterproof(),
        event: GraphEvent::CounterProofNackConfirmed(event.clone()),
        expected_state: GraphState::AllNackd {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            signatures: Default::default(),
            claim_txid: TEST_GRAPH_SUMMARY.claim,
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_payout_txid: TEST_GRAPH_SUMMARY.contested_payout,
            possible_slash_txid: TEST_GRAPH_SUMMARY.slash,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn event_accepted_nonpov() {
    let event = nack_event(TEST_NONPOV_IDX);

    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        GraphTransition {
            from_state: counter_proof_posted_state_with_counterproof(),
            event: GraphEvent::CounterProofNackConfirmed(event.clone()),
            expected_state: GraphState::AllNackd {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                signatures: Default::default(),
                claim_txid: TEST_GRAPH_SUMMARY.claim,
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                expected_payout_txid: TEST_GRAPH_SUMMARY.contested_payout,
                possible_slash_txid: TEST_GRAPH_SUMMARY.slash,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn event_duplicate() {
    let event = nack_event(TEST_NONPOV_IDX);

    let counterproof_txid = TEST_GRAPH_SUMMARY.counterproofs[0].counterproof;
    let mut counterproofs_and_confs = BTreeMap::new();
    counterproofs_and_confs.insert(TEST_NONPOV_IDX, (counterproof_txid, LATER_BLOCK_HEIGHT));

    let mut existing_nacks = BTreeMap::new();
    existing_nacks.insert(TEST_NONPOV_IDX, generate_txid());

    let from_state = GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: Default::default(),
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        counterproofs_and_confs,
        counterproof_nacks: existing_nacks,
    };

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state,
        event: GraphEvent::CounterProofNackConfirmed(event),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn event_duplicate_from_all_nackd() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: all_nackd_state(),
        event: GraphEvent::CounterProofNackConfirmed(nack_event(TEST_NONPOV_IDX)),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn event_rejected_no_counterproof_posted() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_state(),
        event: GraphEvent::CounterProofNackConfirmed(nack_event(TEST_NONPOV_IDX)),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_invalid_operator_idx() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_state_with_counterproof(),
        event: GraphEvent::CounterProofNackConfirmed(nack_event(u32::MAX)),
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
            event: GraphEvent::CounterProofNackConfirmed(nack_event(TEST_NONPOV_IDX)),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

fn state_is_valid(state: &GraphState) -> bool {
    matches!(
        state,
        GraphState::CounterProofPosted { .. } | GraphState::AllNackd { .. }
    )
}
