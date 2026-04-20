//! Unit tests for processing of counterproof NACK confirmation.
//!
//! Tests use a two-slot graph summary ([`build_test_graph_summary(2)`]) so that the
//! `AllNackd` transition requires two NACKs — one per watchtower slot.

use std::collections::BTreeMap;

use strata_bridge_test_utils::prelude::generate_txid;
use strata_bridge_tx_graph::game_graph::GameGraphSummary;

use crate::{
    graph::{
        errors::GSMError,
        events::{CounterProofNackConfirmedEvent, GraphEvent},
        machine::GraphSM,
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,
            build_test_graph_summary, create_nonpov_sm, get_state,
            mock_states::{
                TEST_FULFILLMENT_TXID, all_nackd_state, all_state_variants,
                counter_proof_posted_state,
            },
            test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
            test_graph_transition,
        },
    },
    testing::test_transition,
};

/// A second non-POV operator index for multi-slot tests.
const SECOND_NONPOV_IDX: u32 = 2;

/// Graph summary with two counterproof slots.
fn test_graph_summary() -> GameGraphSummary {
    build_test_graph_summary(2)
}

/// Creates a nack event for the given counterprover.
fn nack_event(counterprover_idx: u32) -> CounterProofNackConfirmedEvent {
    CounterProofNackConfirmedEvent {
        counterproof_nack_txid: generate_txid(),
        counterprover_idx,
    }
}

/// Builds a `CounterProofPosted` state with two watchtower slots, counterproofs posted by
/// both non-POV operators, and `nacked_idxs` already nacked.
fn counter_proof_posted_state_with_nacks(nacked_idxs: &[u32]) -> GraphState {
    let summary = test_graph_summary();
    let counterproof_txid = summary.counterproofs[0].counterproof;

    GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: summary,
        signatures: Default::default(),
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_proof: None,
        counterproofs_and_confs: BTreeMap::from([
            (TEST_NONPOV_IDX, (counterproof_txid, LATER_BLOCK_HEIGHT)),
            (SECOND_NONPOV_IDX, (counterproof_txid, LATER_BLOCK_HEIGHT)),
        ]),
        counterproof_nacks: nacked_idxs
            .iter()
            .map(|&idx| (idx, generate_txid()))
            .collect(),
    }
}

#[test]
fn first_nack_stays_in_counter_proof_posted() {
    let summary = test_graph_summary();
    let counterproof_txid = summary.counterproofs[0].counterproof;
    let from_state = counter_proof_posted_state_with_nacks(&[]);
    let event = nack_event(TEST_NONPOV_IDX);

    test_graph_transition(GraphTransition {
        from_state,
        event: GraphEvent::CounterProofNackConfirmed(event.clone()),
        expected_state: GraphState::CounterProofPosted {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: summary,
            signatures: Default::default(),
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            refuted_proof: None,
            counterproofs_and_confs: BTreeMap::from([
                (TEST_NONPOV_IDX, (counterproof_txid, LATER_BLOCK_HEIGHT)),
                (SECOND_NONPOV_IDX, (counterproof_txid, LATER_BLOCK_HEIGHT)),
            ]),
            counterproof_nacks: BTreeMap::from([(TEST_NONPOV_IDX, event.counterproof_nack_txid)]),
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn second_nack_transitions_to_all_nackd() {
    let summary = test_graph_summary();
    let event = nack_event(SECOND_NONPOV_IDX);

    test_graph_transition(GraphTransition {
        from_state: counter_proof_posted_state_with_nacks(&[TEST_NONPOV_IDX]),
        event: GraphEvent::CounterProofNackConfirmed(event),
        expected_state: GraphState::AllNackd {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            signatures: Default::default(),
            claim_txid: summary.claim,
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_payout_txid: summary.contested_payout,
            possible_slash_txid: summary.slash,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn second_nack_transitions_to_all_nackd_nonpov() {
    let summary = test_graph_summary();
    let event = nack_event(SECOND_NONPOV_IDX);

    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        GraphTransition {
            from_state: counter_proof_posted_state_with_nacks(&[TEST_NONPOV_IDX]),
            event: GraphEvent::CounterProofNackConfirmed(event),
            expected_state: GraphState::AllNackd {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                signatures: Default::default(),
                claim_txid: summary.claim,
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                expected_payout_txid: summary.contested_payout,
                possible_slash_txid: summary.slash,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn event_duplicate() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_state_with_nacks(&[TEST_NONPOV_IDX]),
        event: GraphEvent::CounterProofNackConfirmed(nack_event(TEST_NONPOV_IDX)),
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
        from_state: counter_proof_posted_state_with_nacks(&[]),
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
