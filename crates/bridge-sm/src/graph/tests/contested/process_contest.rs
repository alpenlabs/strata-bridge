//! Unit tests for processing of the contest confirmation.

use bitcoin::{Txid, hashes::Hash};
use strata_bridge_tx_graph::game_graph::GameConnectors;

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
            test_graph_sm_ctx,
        },
    },
    testing::test_transition,
};

/// Block height at which the contest transaction was confirmed.
const CONTEST_BLOCK_HEIGHT: u64 = 200;

#[test]
fn test_contest_from_claimed_pov_emits_duty() {
    let cfg = test_graph_sm_cfg();
    let ctx = test_graph_sm_ctx();
    let deposit_params = test_deposit_params();
    let setup_params = ctx.generate_setup_params(&cfg);
    let connectors = GameConnectors::new(
        deposit_params.game_index,
        &cfg.game_graph_params,
        &setup_params,
    );

    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_sm,
        get_state,
        cfg,
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
                graph_data: deposit_params,
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures: Default::default(),
                fulfillment_txid: Some(TEST_GRAPH_SUMMARY.claim),
                fulfillment_block_height: Some(140),
                contest_block_height: CONTEST_BLOCK_HEIGHT,
            },
            expected_duties: vec![GraphDuty::GenerateAndPublishBridgeProof {
                graph_idx: ctx.graph_idx(),
                contest_txid: TEST_GRAPH_SUMMARY.contest,
                game_index: deposit_params.game_index,
                contest_proof_connector: connectors.contest_proof,
            }],
            expected_signals: vec![],
        },
    );
}

#[test]
fn test_contest_from_claimed_nonpov_no_duty() {
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
