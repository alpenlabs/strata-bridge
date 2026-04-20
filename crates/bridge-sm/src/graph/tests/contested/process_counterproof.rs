//! Unit tests for processing of the counterproof confirmation.

use std::collections::BTreeMap;

use bitcoin::{Txid, hashes::Hash};
use strata_bridge_tx_graph::{
    game_graph::GameConnectors,
    transactions::prelude::{CounterproofNackData, CounterproofNackTx},
};

use crate::{
    graph::{
        duties::GraphDuty,
        errors::GSMError,
        events::{CounterProofConfirmedEvent, GraphEvent},
        machine::GraphSM,
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,
            TEST_POV_IDX, create_nonpov_sm, dummy_proof_receipt, get_state,
            mock_states::{
                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_state_variants,
                bridge_proof_posted_state, contested_state,
            },
            test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
            test_graph_sm_ctx, test_graph_transition,
        },
        watchtower::watchtower_slot_for_operator,
    },
    testing::test_transition,
};

/// Block height at which the counterproof transaction was confirmed.
const COUNTERPROOF_BLOCK_HEIGHT: u64 = LATER_BLOCK_HEIGHT + 50;

/// Creates a counterproof event for the given operator index using the test graph summary.
fn counterproof_event(counterprover_idx: u32) -> CounterProofConfirmedEvent {
    let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, counterprover_idx)
        .expect("counterprover should have a watchtower slot");

    CounterProofConfirmedEvent {
        counterproof_txid: TEST_GRAPH_SUMMARY.counterproofs[watchtower_slot].counterproof,
        counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,
        counterprover_idx,
    }
}

/// Builds the expected `PublishCounterProofNack` duty that the POV operator should emit.
fn expected_nack_duty(counterprover_idx: u32) -> GraphDuty {
    let cfg = test_graph_sm_cfg();
    let ctx = test_graph_sm_ctx();
    let deposit_params = test_deposit_params();
    let setup_params = ctx.generate_setup_params(&cfg);
    let connectors = GameConnectors::new(
        deposit_params.game_index,
        &cfg.game_graph_params,
        &setup_params,
    );

    let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, counterprover_idx)
        .expect("counterprover should have a watchtower slot");

    let counterproof_connector = connectors.counterproof[watchtower_slot];

    let nack_data = CounterproofNackData {
        counterproof_txid: TEST_GRAPH_SUMMARY.counterproofs[watchtower_slot].counterproof,
    };
    let counterproof_nack_tx = CounterproofNackTx::new(nack_data, counterproof_connector);

    GraphDuty::PublishCounterProofNack {
        deposit_idx: ctx.deposit_idx(),
        counter_prover_idx: counterprover_idx,
        counterproof_nack_tx: counterproof_nack_tx.as_ref().clone(),
    }
}

// ===== From Contested =====

#[test]
fn event_accepted_from_contested_pov() {
    let event = counterproof_event(TEST_NONPOV_IDX);

    let mut expected_counterproofs = BTreeMap::new();
    expected_counterproofs.insert(
        event.counterprover_idx,
        (event.counterproof_txid, event.counterproof_block_height),
    );

    test_graph_transition(GraphTransition {
        from_state: contested_state(),
        event: GraphEvent::CounterProofConfirmed(event.clone()),
        expected_state: GraphState::CounterProofPosted {
            last_block_height: COUNTERPROOF_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: TEST_GRAPH_SUMMARY.clone(),
            signatures: vec![],
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            refuted_proof: None,
            counterproofs_and_confs: expected_counterproofs,
            counterproof_nacks: BTreeMap::new(),
        },
        expected_duties: vec![expected_nack_duty(TEST_NONPOV_IDX)],
        expected_signals: vec![],
    });
}

#[test]
fn event_accepted_from_contested_nonpov() {
    let event = counterproof_event(TEST_NONPOV_IDX);

    let mut expected_counterproofs = BTreeMap::new();
    expected_counterproofs.insert(
        event.counterprover_idx,
        (event.counterproof_txid, event.counterproof_block_height),
    );

    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        GraphTransition {
            from_state: contested_state(),
            event: GraphEvent::CounterProofConfirmed(event.clone()),
            expected_state: GraphState::CounterProofPosted {
                last_block_height: COUNTERPROOF_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures: vec![],
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                refuted_proof: None,
                counterproofs_and_confs: expected_counterproofs,
                counterproof_nacks: BTreeMap::new(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

// ===== From BridgeProofPosted =====

#[test]
fn event_accepted_from_bridge_proof_posted_pov() {
    let event = counterproof_event(TEST_NONPOV_IDX);

    let mut expected_counterproofs = BTreeMap::new();
    expected_counterproofs.insert(
        event.counterprover_idx,
        (event.counterproof_txid, event.counterproof_block_height),
    );

    test_graph_transition(GraphTransition {
        from_state: bridge_proof_posted_state(),
        event: GraphEvent::CounterProofConfirmed(event.clone()),
        expected_state: GraphState::CounterProofPosted {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: TEST_GRAPH_SUMMARY.clone(),
            signatures: vec![],
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            refuted_proof: Some(dummy_proof_receipt()),
            counterproofs_and_confs: expected_counterproofs,
            counterproof_nacks: BTreeMap::new(),
        },
        expected_duties: vec![expected_nack_duty(TEST_NONPOV_IDX)],
        expected_signals: vec![],
    });
}

#[test]
fn event_accepted_from_bridge_proof_posted_nonpov() {
    let event = counterproof_event(TEST_NONPOV_IDX);

    let mut expected_counterproofs = BTreeMap::new();
    expected_counterproofs.insert(
        event.counterprover_idx,
        (event.counterproof_txid, event.counterproof_block_height),
    );

    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        GraphTransition {
            from_state: bridge_proof_posted_state(),
            event: GraphEvent::CounterProofConfirmed(event.clone()),
            expected_state: GraphState::CounterProofPosted {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures: vec![],
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                refuted_proof: Some(dummy_proof_receipt()),
                counterproofs_and_confs: expected_counterproofs,
                counterproof_nacks: BTreeMap::new(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

// ===== From CounterProofPosted (accumulation) =====

#[test]
fn event_accepted_from_counter_proof_posted_pov() {
    let event = counterproof_event(TEST_NONPOV_IDX);

    let mut expected_counterproofs = BTreeMap::new();
    expected_counterproofs.insert(
        event.counterprover_idx,
        (event.counterproof_txid, event.counterproof_block_height),
    );

    // Start from an empty CounterProofPosted state (no prior counterproofs).
    let from_state = GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: vec![],
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_proof: None,
        counterproofs_and_confs: BTreeMap::new(),
        counterproof_nacks: BTreeMap::new(),
    };

    test_graph_transition(GraphTransition {
        from_state,
        event: GraphEvent::CounterProofConfirmed(event.clone()),
        expected_state: GraphState::CounterProofPosted {
            last_block_height: COUNTERPROOF_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: TEST_GRAPH_SUMMARY.clone(),
            signatures: vec![],
            fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
            contest_block_height: LATER_BLOCK_HEIGHT,
            refuted_proof: None,
            counterproofs_and_confs: expected_counterproofs,
            counterproof_nacks: BTreeMap::new(),
        },
        expected_duties: vec![expected_nack_duty(TEST_NONPOV_IDX)],
        expected_signals: vec![],
    });
}

// ===== Error Cases =====

#[test]
fn event_duplicate() {
    let event = counterproof_event(TEST_NONPOV_IDX);

    let mut existing_counterproofs = BTreeMap::new();
    existing_counterproofs.insert(
        event.counterprover_idx,
        (event.counterproof_txid, event.counterproof_block_height),
    );

    let from_state = GraphState::CounterProofPosted {
        last_block_height: COUNTERPROOF_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: vec![],
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_proof: None,
        counterproofs_and_confs: existing_counterproofs,
        counterproof_nacks: BTreeMap::new(),
    };

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state,
        event: GraphEvent::CounterProofConfirmed(event),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn event_rejected_invalid_txid() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: contested_state(),
        event: GraphEvent::CounterProofConfirmed(CounterProofConfirmedEvent {
            counterproof_txid: Txid::all_zeros(),
            counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,
            counterprover_idx: TEST_NONPOV_IDX,
        }),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_invalid_operator_idx() {
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: contested_state(),
        event: GraphEvent::CounterProofConfirmed(CounterProofConfirmedEvent {
            counterproof_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof,
            counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,
            counterprover_idx: u32::MAX,
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
            event: GraphEvent::CounterProofConfirmed(counterproof_event(TEST_NONPOV_IDX)),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

/// Returns `true` if the state is valid for [`GraphEvent::CounterProofConfirmed`].
fn state_is_valid(state: &GraphState) -> bool {
    matches!(
        state,
        GraphState::Contested { .. }
            | GraphState::BridgeProofPosted { .. }
            | GraphState::CounterProofPosted { .. }
    )
}
