//! Unit tests for processing of the contest confirmation.

use bitcoin::{Txid, hashes::Hash};

use crate::{
    graph::{
        duties::GraphDuty,
        errors::GSMError,
        events::{ContestConfirmedEvent, GraphEvent},
        machine::GraphSM,
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, create_nonpov_sm,
            create_sm, get_state,
            mock_states::{TEST_GRAPH_SUMMARY, all_state_variants, claimed_state, contested_state},
            test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
        },
    },
    state_machine::StateMachine,
    testing::test_transition,
};

/// Block height at which the contest transaction was confirmed.
const CONTEST_BLOCK_HEIGHT: u64 = 200;

#[test]
fn test_contest_from_claimed_pov_emits_duty() {
    let cfg = test_graph_sm_cfg();

    let mut sm = create_sm(claimed_state(
        LATER_BLOCK_HEIGHT,
        TEST_GRAPH_SUMMARY.claim,
        Default::default(),
    ));

    let result = sm
        .process_event(
            cfg,
            GraphEvent::ContestConfirmed(ContestConfirmedEvent {
                contest_txid: TEST_GRAPH_SUMMARY.contest,
                contest_block_height: CONTEST_BLOCK_HEIGHT,
            }),
        )
        .expect("transition should succeed");

    assert!(
        matches!(sm.state(), GraphState::Contested { .. }),
        "Expected Contested state"
    );
    assert_eq!(result.duties.len(), 1, "Expected exactly one duty");
    assert!(
        matches!(
            &result.duties[0],
            GraphDuty::GenerateAndPublishBridgeProof {
                contest_txid,
                game_index,
                ..
            } if *contest_txid == TEST_GRAPH_SUMMARY.contest
              && game_index.get() == test_deposit_params().game_index.get()
        ),
        "Expected GenerateAndPublishBridgeProof duty with correct fields"
    );
}

#[test]
fn test_contest_from_claimed_nonpov_no_duty() {
    let cfg = test_graph_sm_cfg();

    let mut sm = create_nonpov_sm(claimed_state(
        LATER_BLOCK_HEIGHT,
        TEST_GRAPH_SUMMARY.claim,
        Default::default(),
    ));

    let result = sm
        .process_event(
            cfg,
            GraphEvent::ContestConfirmed(ContestConfirmedEvent {
                contest_txid: TEST_GRAPH_SUMMARY.contest,
                contest_block_height: CONTEST_BLOCK_HEIGHT,
            }),
        )
        .expect("transition should succeed");

    assert!(
        matches!(sm.state(), GraphState::Contested { .. }),
        "Expected Contested state"
    );
    assert!(
        result.duties.is_empty(),
        "Non-POV operator should not emit duties"
    );
}

#[test]
fn test_contest_state_fields() {
    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        GraphTransition {
            from_state: claimed_state(
                LATER_BLOCK_HEIGHT,
                TEST_GRAPH_SUMMARY.claim,
                Default::default(),
            ),
            event: GraphEvent::ContestConfirmed(ContestConfirmedEvent {
                contest_txid: TEST_GRAPH_SUMMARY.contest,
                contest_block_height: CONTEST_BLOCK_HEIGHT,
            }),
            expected_state: GraphState::Contested {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures: Default::default(),
                fulfillment_txid: Some(TEST_GRAPH_SUMMARY.claim),
                fulfillment_block_height: Some(140),
                contest_block_height: CONTEST_BLOCK_HEIGHT,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn test_duplicate_contest() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: contested_state(),
        event: GraphEvent::ContestConfirmed(ContestConfirmedEvent {
            contest_txid: TEST_GRAPH_SUMMARY.contest,
            contest_block_height: CONTEST_BLOCK_HEIGHT,
        }),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn test_contest_rejected_invalid_txid() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: claimed_state(
            LATER_BLOCK_HEIGHT,
            TEST_GRAPH_SUMMARY.claim,
            Default::default(),
        ),
        event: GraphEvent::ContestConfirmed(ContestConfirmedEvent {
            contest_txid: Txid::all_zeros(),
            contest_block_height: CONTEST_BLOCK_HEIGHT,
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn test_contest_from_invalid_state() {
    for from_state in all_state_variants().into_iter().filter(|state| {
        !matches!(
            state,
            GraphState::Claimed { .. } | GraphState::Contested { .. }
        )
    }) {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state,
            event: GraphEvent::ContestConfirmed(ContestConfirmedEvent {
                contest_txid: TEST_GRAPH_SUMMARY.contest,
                contest_block_height: CONTEST_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
