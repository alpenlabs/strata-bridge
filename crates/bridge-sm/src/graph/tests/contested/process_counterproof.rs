//! Unit tests for processing of the counterproof confirmation.

use std::collections::BTreeMap;

use bitcoin::Witness;
use strata_bridge_test_utils::bitcoin::generate_tx;
use strata_bridge_tx_graph::{
    game_graph::GameConnectors,
    transactions::prelude::{CounterproofNackData, CounterproofNackTx},
};

use crate::{
    graph::{
        duties::GraphDuty,
        errors::GSMError,
        events::{
            CounterProofAckConfirmedEvent, CounterProofConfirmedEvent, GraphEvent, NewBlockEvent,
        },
        machine::{GraphSM, generate_game_graph},
        state::{CounterproofData, GraphState},
        tests::{
            GraphInvalidTransition, GraphTransition, LATER_BLOCK_HEIGHT, N_TEST_OPERATORS,
            TEST_NONPOV_IDX, TEST_POV_IDX, create_nonpov_sm, create_sm, dummy_proof_receipt,
            get_state, mock_game_signatures,
            mock_states::{
                TEST_BRIDGE_PROOF_TX, TEST_FULFILLMENT_TXID, TEST_GRAPH_SUMMARY,
                all_state_variants, bridge_proof_posted_state, contested_state,
            },
            test_completed_signatures, test_counterproof_tx, test_deposit_params,
            test_graph_invalid_transition, test_graph_sm_cfg, test_graph_sm_ctx,
            test_graph_transition, test_operator_table,
        },
        watchtower::watchtower_slot_for_operator,
    },
    state_machine::StateMachine,
    testing::test_transition,
};

/// Block height at which the counterproof transaction was confirmed.
const COUNTERPROOF_BLOCK_HEIGHT: u64 = LATER_BLOCK_HEIGHT + 50;

/// Creates a counterproof event for the given operator index using the test graph summary.
fn counterproof_event(counterprover_idx: u32) -> CounterProofConfirmedEvent {
    watchtower_slot_for_operator(
        test_graph_sm_ctx().operator_table(),
        TEST_POV_IDX,
        counterprover_idx,
    )
    .expect("counterprover should have a watchtower slot");

    CounterProofConfirmedEvent {
        counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,
        tx: test_counterproof_tx(),
        counterprover_idx,
    }
}

/// Builds the expected `PublishCounterProofNack` duty that the POV operator should emit.
fn expected_nack_duty(counterprover_idx: u32) -> GraphDuty {
    let cfg = test_graph_sm_cfg();
    let ctx = test_graph_sm_ctx();
    let deposit_params = test_deposit_params();
    let setup_params = ctx.generate_setup_params(&cfg, &deposit_params);
    let connectors = GameConnectors::new(
        deposit_params.game_index,
        &cfg.game_graph_params,
        &setup_params,
    );

    let watchtower_slot = watchtower_slot_for_operator(
        test_graph_sm_ctx().operator_table(),
        TEST_POV_IDX,
        counterprover_idx,
    )
    .expect("counterprover should have a watchtower slot");

    let counterproof_connector = connectors.counterproof[watchtower_slot];

    let nack_data = CounterproofNackData {
        counterproof_txid: TEST_GRAPH_SUMMARY.counterproofs[watchtower_slot].counterproof,
    };
    let counterproof_nack_tx = CounterproofNackTx::new(nack_data, counterproof_connector);

    GraphDuty::PublishCounterProofNack {
        deposit_idx: ctx.deposit_idx(),
        counterprover_idx,
        completed_signatures: test_completed_signatures(),
        counterproof_nack_tx,
    }
}

// ===== From Contested =====

#[test]
fn event_accepted_from_contested_pov() {
    let event = counterproof_event(TEST_NONPOV_IDX);

    let mut expected_counterproofs = BTreeMap::new();
    expected_counterproofs.insert(
        event.counterprover_idx,
        CounterproofData {
            txid: event.tx.compute_txid(),
            conf_height: event.counterproof_block_height,
            completed_signatures: Some(test_completed_signatures()),
        },
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
            refuted_bridge_proof: None,
            counterproofs_and_confs: expected_counterproofs,
            counterproof_nacks: BTreeMap::new(),
            stake_spent: None,
            payout_connector_spent: None,
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
        CounterproofData {
            txid: event.tx.compute_txid(),
            conf_height: event.counterproof_block_height,
            completed_signatures: Some(test_completed_signatures()),
        },
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
                refuted_bridge_proof: None,
                counterproofs_and_confs: expected_counterproofs,
                counterproof_nacks: BTreeMap::new(),
                stake_spent: None,
                payout_connector_spent: None,
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
        CounterproofData {
            txid: event.tx.compute_txid(),
            conf_height: event.counterproof_block_height,
            completed_signatures: Some(test_completed_signatures()),
        },
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
            refuted_bridge_proof: Some((TEST_BRIDGE_PROOF_TX.clone(), dummy_proof_receipt())),
            counterproofs_and_confs: expected_counterproofs,
            counterproof_nacks: BTreeMap::new(),
            stake_spent: None,
            payout_connector_spent: None,
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
        CounterproofData {
            txid: event.tx.compute_txid(),
            conf_height: event.counterproof_block_height,
            completed_signatures: Some(test_completed_signatures()),
        },
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
                refuted_bridge_proof: Some((TEST_BRIDGE_PROOF_TX.clone(), dummy_proof_receipt())),
                counterproofs_and_confs: expected_counterproofs,
                counterproof_nacks: BTreeMap::new(),
                stake_spent: None,
                payout_connector_spent: None,
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
        CounterproofData {
            txid: event.tx.compute_txid(),
            conf_height: event.counterproof_block_height,
            completed_signatures: Some(test_completed_signatures()),
        },
    );

    // Start from an empty CounterProofPosted state (no prior counterproofs).
    let from_state = GraphState::CounterProofPosted {
        last_block_height: LATER_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: vec![],
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_bridge_proof: None,
        counterproofs_and_confs: BTreeMap::new(),
        counterproof_nacks: BTreeMap::new(),
        stake_spent: None,
        payout_connector_spent: None,
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
            refuted_bridge_proof: None,
            counterproofs_and_confs: expected_counterproofs,
            counterproof_nacks: BTreeMap::new(),
            stake_spent: None,
            payout_connector_spent: None,
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
        CounterproofData {
            txid: event.tx.compute_txid(),
            conf_height: event.counterproof_block_height,
            completed_signatures: Some(test_completed_signatures()),
        },
    );

    let from_state = GraphState::CounterProofPosted {
        last_block_height: COUNTERPROOF_BLOCK_HEIGHT,
        graph_data: test_deposit_params(),
        graph_summary: TEST_GRAPH_SUMMARY.clone(),
        signatures: vec![],
        fulfillment_txid: Some(*TEST_FULFILLMENT_TXID),
        contest_block_height: LATER_BLOCK_HEIGHT,
        refuted_bridge_proof: None,
        counterproofs_and_confs: existing_counterproofs,
        counterproof_nacks: BTreeMap::new(),
        stake_spent: None,
        payout_connector_spent: None,
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
            counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,
            tx: generate_tx(0, 0),
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
            counterproof_block_height: COUNTERPROOF_BLOCK_HEIGHT,
            tx: test_counterproof_tx(),
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

#[test]
fn confirmed_counterproof_is_recorded_without_decodable_signatures() {
    let mut malformed = test_counterproof_tx().input[0].witness.to_vec();
    malformed[0] = vec![0; 32];
    let mut invalid_hash_type = test_counterproof_tx().input[0].witness.to_vec();
    invalid_hash_type[0].push(0xff);
    for witness in [
        Witness::new(),
        Witness::from_slice(&malformed),
        Witness::from_slice(&invalid_hash_type),
    ] {
        for from_state in [contested_state(), bridge_proof_posted_state()] {
            for create in [create_sm, create_nonpov_sm] {
                let mut sm = create(from_state.clone());
                let mut event = counterproof_event(TEST_NONPOV_IDX);
                event.tx.input[0].witness = witness.clone();
                let output = sm
                    .process_event(test_graph_sm_cfg(), event.clone().into())
                    .unwrap();
                assert!(output.duties.is_empty());
                let GraphState::CounterProofPosted {
                    counterproofs_and_confs,
                    ..
                } = sm.state()
                else {
                    panic!("confirmed counterproof must be recorded");
                };
                assert_eq!(
                    counterproofs_and_confs[&TEST_NONPOV_IDX],
                    CounterproofData {
                        txid: event.tx.compute_txid(),
                        conf_height: event.counterproof_block_height,
                        completed_signatures: None,
                    }
                );
                let bytes = postcard::to_allocvec(&sm).unwrap();
                let mut restored: GraphSM = postcard::from_bytes(&bytes).unwrap();
                assert_eq!(restored, sm);
                assert!(matches!(
                    restored.process_event(test_graph_sm_cfg(), event.into()),
                    Err(GSMError::Duplicate { .. })
                ));
            }
        }
    }
}

#[test]
fn confirmed_signatures_support_taproot_encodings_and_annex() {
    // These are decoder fixtures; consensus validation belongs to the chain source.
    for hash_type in [
        None,
        Some(1),
        Some(2),
        Some(3),
        Some(0x81),
        Some(0x82),
        Some(0x83),
    ] {
        for annex in [false, true] {
            let mut event = counterproof_event(TEST_NONPOV_IDX);
            let mut witness = event.tx.input[0].witness.to_vec();
            if let Some(hash_type) = hash_type {
                witness[0].push(hash_type);
            }
            if annex {
                witness.push(vec![0x50, 1, 2]);
            }
            event.tx.input[0].witness = Witness::from_slice(&witness);
            let mut sm = create_sm(contested_state());
            let output = sm.process_event(test_graph_sm_cfg(), event.into()).unwrap();
            assert_eq!(output.duties, vec![expected_nack_duty(TEST_NONPOV_IDX)]);
            let GraphState::CounterProofPosted {
                counterproofs_and_confs,
                ..
            } = sm.state()
            else {
                unreachable!()
            };
            assert_eq!(
                counterproofs_and_confs[&TEST_NONPOV_IDX].completed_signatures,
                Some(test_completed_signatures())
            );
        }
    }
}

#[test]
fn event_rejected_when_counterprover_does_not_own_slot() {
    let mut state = contested_state();
    let GraphState::Contested { graph_summary, .. } = &mut state else {
        unreachable!()
    };
    let mut other_slot = graph_summary.counterproofs[0];
    other_slot.counterproof = generate_tx(1, 1).compute_txid();
    graph_summary.counterproofs.push(other_slot);
    test_graph_invalid_transition(GraphInvalidTransition {
        from_state: state,
        event: counterproof_event(2).into(),
        expected_error: |e| matches!(e, GSMError::Rejected { .. }),
    });
}

#[test]
fn each_watchtower_can_ack_its_confirmed_slot_after_restart() {
    let cfg = test_graph_sm_cfg();
    let game = generate_game_graph(&cfg, &test_graph_sm_ctx(), &test_deposit_params());
    let confirmation_height = LATER_BLOCK_HEIGHT + 1;
    let boundary = confirmation_height + u64::from(cfg.game_graph_params.nack_timelock.value());
    for available in [false, true] {
        for pov in 1..N_TEST_OPERATORS as u32 {
            let mut sm = create_sm(bridge_proof_posted_state());
            sm.context.operator_table = test_operator_table(N_TEST_OPERATORS, pov);
            let GraphState::BridgeProofPosted {
                graph_summary,
                signatures,
                ..
            } = &mut sm.state
            else {
                unreachable!()
            };
            *graph_summary = game.summarize();
            *signatures = mock_game_signatures(&game);
            for (slot, graph) in game.counterproofs.iter().enumerate() {
                let mut tx = graph.counterproof.as_ref().clone();
                if available {
                    let mut witness = test_counterproof_tx().input[0].witness.to_vec();
                    witness[0].push(1);
                    tx.input[0].witness = Witness::from_slice(&witness);
                }
                let output = sm
                    .process_event(
                        cfg.clone(),
                        CounterProofConfirmedEvent {
                            counterproof_block_height: confirmation_height,
                            tx,
                            counterprover_idx: slot as u32 + 1,
                        }
                        .into(),
                    )
                    .unwrap();
                assert!(output.duties.is_empty());
            }
            let bytes = postcard::to_allocvec(&sm).unwrap();
            let mut sm: GraphSM = postcard::from_bytes(&bytes).unwrap();
            let GraphState::CounterProofPosted {
                counterproofs_and_confs,
                ..
            } = &sm.state
            else {
                unreachable!()
            };
            assert_eq!(counterproofs_and_confs.len(), game.counterproofs.len());
            assert!(
                sm.process_event(
                    cfg.clone(),
                    NewBlockEvent {
                        block_height: boundary
                    }
                    .into()
                )
                .unwrap()
                .duties
                .is_empty()
            );
            let output = sm
                .process_event(
                    cfg.clone(),
                    NewBlockEvent {
                        block_height: boundary + 1,
                    }
                    .into(),
                )
                .unwrap();
            let [
                GraphDuty::PublishCounterProofAck {
                    signed_counter_proof_ack_tx,
                    ..
                },
            ] = output.duties.as_slice()
            else {
                panic!("watchtower must ACK its confirmed slot after the NACK window");
            };
            let expected = &game.counterproofs[pov as usize - 1].counterproof_ack;
            assert_eq!(
                signed_counter_proof_ack_tx.compute_txid(),
                expected.as_ref().compute_txid()
            );
            sm.process_event(
                cfg.clone(),
                CounterProofAckConfirmedEvent {
                    counterproof_ack_txid: signed_counter_proof_ack_tx.compute_txid(),
                    counterproof_ack_block_height: boundary + 2,
                    counterprover_idx: pov,
                }
                .into(),
            )
            .unwrap();
            assert!(matches!(sm.state, GraphState::Acked { .. }));
        }
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
