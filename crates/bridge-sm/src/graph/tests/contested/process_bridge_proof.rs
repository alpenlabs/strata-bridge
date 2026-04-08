//! Unit tests for processing of the bridge proof confirmation.

use std::sync::Arc;

use bitcoin::{Txid, hashes::Hash};
use strata_bridge_primitives::proof::BridgeProofPredicate;

use crate::{
    graph::{
        duties::GraphDuty,
        errors::GSMError,
        events::{BridgeProofConfirmedEvent, GraphEvent},
        machine::generate_game_graph,
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, create_nonpov_sm,
            create_sm, dummy_proof_receipt, get_state,
            mock_states::{
                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_state_variants,
                bridge_proof_posted_state, contested_state,
            },
            test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
            test_graph_transition,
        },
    },
    testing::test_transition,
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

/// Creates a config with an invalid Sp1Groth16 vkey so proof verification always rejects.
fn cfg_with_reject_predicate() -> Arc<crate::graph::config::GraphSMCfg> {
    let mut cfg = (*test_graph_sm_cfg()).clone();
    cfg.bridge_proof_predicate = BridgeProofPredicate::Sp1Groth16 {
        program_vk_hash: [0xAB; 32],
    };
    Arc::new(cfg)
}

#[test]
fn event_accepted_pov_no_duties() {
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
fn watchtower_skips_counterproof_when_proof_valid() {
    let cfg = test_graph_sm_cfg();
    let event = bridge_proof_event();

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        cfg,
        GraphTransition {
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
        },
    );
}

#[test]
fn watchtower_emits_counterproof_when_proof_invalid() {
    let cfg = cfg_with_reject_predicate();
    let event = bridge_proof_event();
    let sm = create_nonpov_sm(contested_state());

    let game_graph = generate_game_graph(&cfg, sm.context(), test_deposit_params());
    let watchtower_idx = sm.context().watchtower_index();
    let expected_counterproof_tx = game_graph.counterproofs[watchtower_idx as usize]
        .counterproof
        .as_ref()
        .clone();

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        cfg,
        GraphTransition {
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
            expected_duties: vec![GraphDuty::PublishCounterProof {
                graph_idx: sm.context().graph_idx(),
                counterproof_tx: expected_counterproof_tx,
                proof: dummy_proof_receipt(),
            }],
            expected_signals: vec![],
        },
    );
}

#[test]
fn pov_watchtower_skips_counterproof_even_when_proof_invalid() {
    let cfg = cfg_with_reject_predicate();
    let event = bridge_proof_event();

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_sm,
        get_state,
        cfg,
        GraphTransition {
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
        },
    );
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
