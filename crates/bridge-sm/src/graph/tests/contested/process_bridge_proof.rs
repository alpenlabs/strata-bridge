//! Unit tests for processing of the bridge proof confirmation.

use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{Txid, hashes::Hash};
use strata_bridge_test_utils::bitcoin::generate_tx;
use strata_bridge_tx_graph::musig_functor::GameFunctor;
use strata_predicate::PredicateKey;

use crate::{
    graph::{
        duties::GraphDuty,
        errors::GSMError,
        events::{BridgeProofConfirmedEvent, GraphEvent},
        machine::generate_game_graph,
        state::GraphState,
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,
            create_nonpov_sm, create_sm, dummy_proof_receipt, get_state, mock_game_signatures,
            mock_states::{
                TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY, all_state_variants,
                bridge_proof_posted_state, contested_state, contested_state_with,
                counter_proof_posted_state, counter_proof_posted_without_refuted_proof_state,
            },
            test_bridge_proof_tx, test_deposit_params, test_graph_invalid_transition,
            test_graph_sm_cfg, test_graph_transition,
        },
        watchtower::watchtower_slot_for_operator,
    },
    testing::test_transition,
};

/// Block height at which the bridge proof transaction was confirmed.
const BRIDGE_PROOF_BLOCK_HEIGHT: u64 = u64::MAX;

fn bridge_proof_event() -> BridgeProofConfirmedEvent {
    BridgeProofConfirmedEvent {
        bridge_proof_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
        tx: test_bridge_proof_tx(),
        proof: dummy_proof_receipt(),
    }
}

/// Creates a config with a never-accept predicate so proof verification always rejects.
fn cfg_with_reject_predicate() -> Arc<crate::graph::config::GraphSMCfg> {
    let mut cfg = (*test_graph_sm_cfg()).clone();
    cfg.bridge_proof_predicate = PredicateKey::never_accept();
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
            bridge_proof_txid: event.tx.compute_txid(),
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
                bridge_proof_txid: event.tx.compute_txid(),
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

    let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());
    let signatures = mock_game_signatures(&game_graph);
    let watchtower_idx = watchtower_slot_for_operator(
        sm.context().operator_idx(),
        sm.context().operator_table().pov_idx(),
    )
    .expect("graph owner has no watchtower index");
    let expected_counterproof_tx = game_graph.counterproofs[watchtower_idx]
        .counterproof
        .clone();
    let expected_n_of_n_sig =
        GameFunctor::unpack(signatures.clone(), sm.context().watchtower_pubkeys().len())
            .expect("unpack must succeed")
            .watchtowers[watchtower_idx]
            .counterproof[0];

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        cfg,
        GraphTransition {
            from_state: contested_state_with(LATER_BLOCK_HEIGHT, signatures.clone()),
            event: GraphEvent::BridgeProofConfirmed(event.clone()),
            expected_state: GraphState::BridgeProofPosted {
                last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures,
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                bridge_proof_txid: event.tx.compute_txid(),
                bridge_proof_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
                proof: dummy_proof_receipt(),
            },
            expected_duties: vec![GraphDuty::GenerateAndPublishCounterProof {
                graph_idx: sm.context().graph_idx(),
                counterproof_tx: expected_counterproof_tx,
                watchtower_idx: watchtower_idx as u32,
                n_of_n_signature: expected_n_of_n_sig,
                proof: dummy_proof_receipt(),
            }],
            expected_signals: vec![],
        },
    );
}

#[test]
fn accepts_bridge_proof_posted_after_counterproof() {
    let event = bridge_proof_event();

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        test_graph_sm_cfg(),
        GraphTransition {
            from_state: counter_proof_posted_without_refuted_proof_state(),
            event: GraphEvent::BridgeProofConfirmed(event),
            expected_state: GraphState::CounterProofPosted {
                last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures: vec![],
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                refuted_proof: Some(dummy_proof_receipt()),
                counterproofs_and_confs: Default::default(),
                counterproof_nacks: Default::default(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn watchtower_emits_counterproof_when_late_proof_invalid() {
    let cfg = cfg_with_reject_predicate();
    let event = bridge_proof_event();
    let sm = create_nonpov_sm(counter_proof_posted_without_refuted_proof_state());

    let game_graph = generate_game_graph(&cfg, sm.context(), &test_deposit_params());
    let signatures = mock_game_signatures(&game_graph);
    let watchtower_idx = watchtower_slot_for_operator(
        sm.context().operator_idx(),
        sm.context().operator_table().pov_idx(),
    )
    .expect("graph owner has no watchtower index");
    let expected_counterproof_tx = game_graph.counterproofs[watchtower_idx]
        .counterproof
        .clone();
    let expected_n_of_n_sig =
        GameFunctor::unpack(signatures.clone(), sm.context().watchtower_pubkeys().len())
            .expect("unpack must succeed")
            .watchtowers[watchtower_idx]
            .counterproof[0];

    let from_state = GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: signatures.clone(),
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_proof: None,
        counterproofs_and_confs: Default::default(),
        counterproof_nacks: Default::default(),
    };

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        cfg,
        GraphTransition {
            from_state,
            event: GraphEvent::BridgeProofConfirmed(event.clone()),
            expected_state: GraphState::CounterProofPosted {
                last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures,
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                refuted_proof: Some(dummy_proof_receipt()),
                counterproofs_and_confs: Default::default(),
                counterproof_nacks: Default::default(),
            },
            expected_duties: vec![GraphDuty::GenerateAndPublishCounterProof {
                graph_idx: sm.context().graph_idx(),
                counterproof_tx: expected_counterproof_tx,
                watchtower_idx: watchtower_idx as u32,
                n_of_n_signature: expected_n_of_n_sig,
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
                bridge_proof_txid: event.tx.compute_txid(),
                bridge_proof_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
                proof: dummy_proof_receipt(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn watchtower_skips_counterproof_when_already_posted_on_late_invalid_proof() {
    let cfg = cfg_with_reject_predicate();
    let event = bridge_proof_event();

    let existing_counterproof_txid = Txid::from_byte_array([0xCD; 32]);
    let mut counterproofs_and_confs = BTreeMap::new();
    counterproofs_and_confs.insert(
        TEST_NONPOV_IDX,
        (existing_counterproof_txid, LATER_BLOCK_HEIGHT),
    );

    let from_state = GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: Default::default(),
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_proof: None,
        counterproofs_and_confs: counterproofs_and_confs.clone(),
        counterproof_nacks: BTreeMap::new(),
    };

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        cfg,
        GraphTransition {
            from_state,
            event: GraphEvent::BridgeProofConfirmed(event),
            expected_state: GraphState::CounterProofPosted {
                last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures: vec![],
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                refuted_proof: Some(dummy_proof_receipt()),
                counterproofs_and_confs,
                counterproof_nacks: BTreeMap::new(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn pov_skips_counterproof_on_late_invalid_proof() {
    let cfg = cfg_with_reject_predicate();
    let event = bridge_proof_event();

    test_transition::<crate::graph::machine::GraphSM, _, _, _, _, _, _, _>(
        create_sm,
        get_state,
        cfg,
        GraphTransition {
            from_state: counter_proof_posted_without_refuted_proof_state(),
            event: GraphEvent::BridgeProofConfirmed(event),
            expected_state: GraphState::CounterProofPosted {
                last_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: TEST_GRAPH_SUMMARY.clone(),
                signatures: vec![],
                fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
                contest_block_height: LATER_BLOCK_HEIGHT,
                refuted_proof: Some(dummy_proof_receipt()),
                counterproofs_and_confs: Default::default(),
                counterproof_nacks: Default::default(),
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

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_state(),
        event: GraphEvent::BridgeProofConfirmed(bridge_proof_event()),
        expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
    });
}

#[test]
fn event_rejected_wrong_outpoint_from_contested() {
    let event = BridgeProofConfirmedEvent {
        bridge_proof_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
        tx: generate_tx(0, 0),
        proof: dummy_proof_receipt(),
    };

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: contested_state(),
        event: GraphEvent::BridgeProofConfirmed(event),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_wrong_outpoint_from_counterproof_posted() {
    let event = BridgeProofConfirmedEvent {
        bridge_proof_block_height: BRIDGE_PROOF_BLOCK_HEIGHT,
        tx: generate_tx(0, 0),
        proof: dummy_proof_receipt(),
    };

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: counter_proof_posted_without_refuted_proof_state(),
        event: GraphEvent::BridgeProofConfirmed(event),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_bridge_proof_timeout_txid_from_contested() {
    // Set bridge_proof_timeout to the bridge proof tx's txid so the validation
    // rejects it even though it spends the correct contest proof connector.
    let event = bridge_proof_event();
    let from_state = contested_state_with_timeout_txid(event.tx.compute_txid());

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state,
        event: GraphEvent::BridgeProofConfirmed(event),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn event_rejected_bridge_proof_timeout_txid_from_counterproof_posted() {
    let event = bridge_proof_event();
    let from_state =
        counter_proof_posted_without_refuted_proof_state_with_timeout_txid(event.tx.compute_txid());

    test_graph_invalid_transition(GraphInvalidTransition {
        from_state,
        event: GraphEvent::BridgeProofConfirmed(event),
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
            event: GraphEvent::BridgeProofConfirmed(bridge_proof_event()),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}

/// Builds a `Contested` state with `bridge_proof_timeout` set to the given txid.
fn contested_state_with_timeout_txid(timeout_txid: bitcoin::Txid) -> GraphState {
    let mut summary = TEST_GRAPH_SUMMARY.clone();
    summary.bridge_proof_timeout = timeout_txid;
    GraphState::Contested {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: summary,
        signatures: Default::default(),
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        fulfillment_block_height: Some(LATER_BLOCK_HEIGHT),
        contest_block_height: LATER_BLOCK_HEIGHT,
    }
}

/// Builds a `CounterProofPosted` state (no refuted proof) with `bridge_proof_timeout` set to the
/// given txid.
fn counter_proof_posted_without_refuted_proof_state_with_timeout_txid(
    timeout_txid: bitcoin::Txid,
) -> GraphState {
    let mut summary = TEST_GRAPH_SUMMARY.clone();
    summary.bridge_proof_timeout = timeout_txid;
    GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: summary,
        signatures: Default::default(),
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_proof: None,
        counterproofs_and_confs: Default::default(),
        counterproof_nacks: Default::default(),
    }
}

/// Returns `true` if the state is valid for [`GraphEvent::BridgeProofConfirmed`].
fn state_is_valid(state: &GraphState) -> bool {
    matches!(state, GraphState::Contested { .. })
        || matches!(state, GraphState::CounterProofPosted { refuted_proof, .. } if refuted_proof.is_none())
        // Yield Duplicate error, but still valid to receive the event:
        || matches!(state, GraphState::BridgeProofPosted { .. })
        || matches!(state, GraphState::CounterProofPosted { refuted_proof, .. } if refuted_proof.is_some())
}
