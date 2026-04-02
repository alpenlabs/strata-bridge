//! Unit Tests for notify_new_block in Claimed state
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::secp256k1::schnorr::Signature;
    use strata_bridge_test_utils::bitcoin::generate_txid;
    use strata_bridge_tx_graph::musig_functor::GameFunctor;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{GraphEvent, NewBlockEvent},
            machine::{GraphSM, generate_game_graph},
            state::GraphState,
            tests::{
                CLAIM_BLOCK_HEIGHT, CONTEST_TIMELOCK_BLOCKS, GraphInvalidTransition,
                GraphTransition, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX,
                TEST_POV_IDX, create_nonpov_sm, create_sm, get_state, mock_game_signatures,
                mock_states::{
                    acked_state, assigned_state, bridge_proof_posted_state_with,
                    bridge_proof_timedout_state_with, claimed_state, contested_state_with,
                    counter_proof_posted_state,
                },
                test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
                test_graph_sm_ctx, test_graph_summary, test_graph_transition, test_recipient_desc,
            },
            watchtower::watchtower_slot_for_operator,
        },
        testing::test_transition,
    };

    fn counter_proof_posted_state_with(
        last_block_height: u64,
        contest_block_height: u64,
        signatures: Vec<Signature>,
        counterproofs_and_confs: BTreeMap<u32, (bitcoin::Txid, u64)>,
    ) -> GraphState {
        let mut state = counter_proof_posted_state();
        if let GraphState::CounterProofPosted {
            last_block_height: state_last_block_height,
            signatures: state_signatures,
            contest_block_height: state_contest_block_height,
            counterproofs_and_confs: state_counterproofs_and_confs,
            ..
        } = &mut state
        {
            *state_last_block_height = last_block_height;
            *state_signatures = signatures;
            *state_contest_block_height = contest_block_height;
            *state_counterproofs_and_confs = counterproofs_and_confs;
        } else {
            panic!("expected CounterProofPosted state");
        }
        state
    }

    fn acked_state_with(
        last_block_height: u64,
        contest_block_height: u64,
        signatures: Vec<Signature>,
    ) -> GraphState {
        let mut state = acked_state();
        if let GraphState::Acked {
            last_block_height: state_last_block_height,
            signatures: state_signatures,
            contest_block_height: state_contest_block_height,
            ..
        } = &mut state
        {
            *state_last_block_height = last_block_height;
            *state_signatures = signatures;
            *state_contest_block_height = contest_block_height;
        } else {
            panic!("expected Acked state");
        }
        state
    }

    // TODO: <https://atlassian.alpenlabs.net/browse/STR-2678>
    // Add a proptest asserting that `NewBlock` events with
    // `block_height <= last_processed_block_height` are rejected and otherwise update
    // `last_block_height`.

    #[test]
    fn test_new_block_claimed_no_timeout() {
        let fulfillment_txid = generate_txid();
        // Exactly at timeout boundary (not exceeded: 160 > 160 is false)
        let new_height = CLAIM_BLOCK_HEIGHT + CONTEST_TIMELOCK_BLOCKS;

        test_graph_transition(GraphTransition {
            from_state: claimed_state(INITIAL_BLOCK_HEIGHT, fulfillment_txid, Default::default()),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: new_height,
            }),
            expected_state: claimed_state(new_height, fulfillment_txid, Default::default()),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_new_block_claimed_timeout_triggers_payout() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let fulfillment_txid = generate_txid();

        // Block height exceeding contest timeout (161 > 160)
        let new_height = CLAIM_BLOCK_HEIGHT + CONTEST_TIMELOCK_BLOCKS + 1;

        // Compute expected finalized uncontested payout transaction
        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let uncontested_sigs =
            GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
                .expect("Failed to unpack signatures")
                .uncontested_payout;
        let signed_uncontested_payout_tx = game_graph.uncontested_payout.finalize(uncontested_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: claimed_state(
                    INITIAL_BLOCK_HEIGHT,
                    fulfillment_txid,
                    signatures.clone(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: claimed_state(new_height, fulfillment_txid, signatures),
                expected_duties: vec![GraphDuty::PublishUncontestedPayout {
                    signed_uncontested_payout_tx,
                }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn test_new_block_claimed_already_processed() {
        let fulfillment_txid = generate_txid();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: claimed_state(INITIAL_BLOCK_HEIGHT, fulfillment_txid, Default::default()),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: INITIAL_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_new_block_claimed_earlier_block_rejected() {
        let fulfillment_txid = generate_txid();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: claimed_state(INITIAL_BLOCK_HEIGHT, fulfillment_txid, Default::default()),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: INITIAL_BLOCK_HEIGHT - 1,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_new_block_created_accepted() {
        test_graph_transition(GraphTransition {
            from_state: GraphState::Created {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: INITIAL_BLOCK_HEIGHT + 1,
            }),
            expected_state: GraphState::Created {
                last_block_height: INITIAL_BLOCK_HEIGHT + 1,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn contested_simple_update() {
        let cfg = test_graph_sm_cfg();
        let contest_height = LATER_BLOCK_HEIGHT;
        let proof_timelock = u64::from(cfg.game_graph_params.proof_timelock.value());
        let new_height = contest_height + proof_timelock;

        test_graph_transition(GraphTransition {
            from_state: contested_state_with(contest_height, vec![]),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: new_height,
            }),
            expected_state: contested_state_with(new_height, vec![]),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn contested_proof_timelock() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let proof_timelock = u64::from(cfg.game_graph_params.proof_timelock.value());
        let new_height = contest_height + proof_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let bridge_proof_timeout_sigs =
            GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
                .expect("Failed to unpack signatures")
                .bridge_proof_timeout;
        let signed_timeout_tx = game_graph
            .bridge_proof_timeout
            .finalize(bridge_proof_timeout_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: contested_state_with(contest_height, signatures.clone()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: contested_state_with(new_height, signatures),
                expected_duties: vec![GraphDuty::PublishBridgeProofTimeout { signed_timeout_tx }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn contested_payout_timeout() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let slash_sigs = GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
            .expect("Failed to unpack signatures")
            .slash;
        let signed_slash_tx = game_graph.slash.finalize(slash_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: contested_state_with(contest_height, signatures.clone()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: contested_state_with(new_height, signatures),
                expected_duties: vec![GraphDuty::PublishSlash { signed_slash_tx }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn bridge_proof_timedout_simple_update() {
        let cfg = test_graph_sm_cfg();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock;

        test_graph_transition(GraphTransition {
            from_state: bridge_proof_timedout_state_with(contest_height, vec![]),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: new_height,
            }),
            expected_state: bridge_proof_timedout_state_with(new_height, vec![]),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn bridge_proof_timedout_payout_timeout() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let slash_sigs = GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
            .expect("Failed to unpack signatures")
            .slash;
        let signed_slash_tx = game_graph.slash.finalize(slash_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: bridge_proof_timedout_state_with(contest_height, signatures.clone()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: bridge_proof_timedout_state_with(new_height, signatures),
                expected_duties: vec![GraphDuty::PublishSlash { signed_slash_tx }],
                expected_signals: vec![],
            },
        );
    }

    // ===== BridgeProofPosted Tests =====

    #[test]
    fn bridge_proof_posted_simple_update() {
        let cfg = test_graph_sm_cfg();
        let contest_height = LATER_BLOCK_HEIGHT;
        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
        // Exactly at ack timeout boundary (not exceeded)
        let new_height = contest_height + ack_timelock;

        test_graph_transition(GraphTransition {
            from_state: bridge_proof_posted_state_with(contest_height, vec![]),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: new_height,
            }),
            expected_state: bridge_proof_posted_state_with(new_height, vec![]),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    // ===== Assigned State Deadline Tests =====

    /// Tests that Assigned state reverts to GraphSigned when fulfillment deadline expires
    #[test]
    fn test_new_block_reverts_assigned_to_graph_signed_when_deadline_exceeded() {
        let deadline = INITIAL_BLOCK_HEIGHT + 10;
        let block_height_after_deadline = deadline + 1;

        test_graph_transition(GraphTransition {
            from_state: assigned_state(TEST_POV_IDX, deadline, test_recipient_desc(1)),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: block_height_after_deadline,
            }),
            expected_state: GraphState::GraphSigned {
                last_block_height: block_height_after_deadline,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                agg_nonces: None,
                signatures: Default::default(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn bridge_proof_posted_already_processed() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: bridge_proof_posted_state_with(LATER_BLOCK_HEIGHT, Default::default()),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: LATER_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn bridge_proof_posted_pov_contested_payout() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
        let new_height = contest_height + ack_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let contested_payout_sigs =
            GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
                .expect("Failed to unpack signatures")
                .contested_payout;
        let signed_contested_payout_tx =
            game_graph.contested_payout.finalize(contested_payout_sigs);

        // POV owns this graph, so contested payout should be emitted
        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: bridge_proof_posted_state_with(contest_height, signatures.clone()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: bridge_proof_posted_state_with(new_height, signatures),
                expected_duties: vec![GraphDuty::PublishContestedPayout {
                    signed_contested_payout_tx,
                }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn bridge_proof_posted_nonpov_no_contested_payout() {
        let cfg = test_graph_sm_cfg();
        let contest_height = LATER_BLOCK_HEIGHT;
        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
        // Exceeds ack timelock, but non-POV should not emit contested payout
        let new_height = contest_height + ack_timelock + 1;

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: bridge_proof_posted_state_with(contest_height, Default::default()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: bridge_proof_posted_state_with(new_height, Default::default()),
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn bridge_proof_posted_nonpov_slash() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let slash_sigs = GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
            .expect("Failed to unpack signatures")
            .slash;
        let signed_slash_tx = game_graph.slash.finalize(slash_sigs);

        // Non-POV should slash (not own graph)
        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: bridge_proof_posted_state_with(contest_height, signatures.clone()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: bridge_proof_posted_state_with(new_height, signatures),
                expected_duties: vec![GraphDuty::PublishSlash { signed_slash_tx }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn bridge_proof_posted_pov_no_slash_when_both_timelocks_exceeded() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        // Exceeds both timelocks; POV should emit contested payout, not slash
        let new_height = contest_height + payout_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let contested_payout_sigs =
            GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
                .expect("Failed to unpack signatures")
                .contested_payout;
        let signed_contested_payout_tx =
            game_graph.contested_payout.finalize(contested_payout_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: bridge_proof_posted_state_with(contest_height, signatures.clone()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: bridge_proof_posted_state_with(new_height, signatures),
                expected_duties: vec![GraphDuty::PublishContestedPayout {
                    signed_contested_payout_tx,
                }],
                expected_signals: vec![],
            },
        );
    }

    // ===== CounterProofPosted Tests =====

    /// Graph owner publishes contested payout after ack timelock expires.
    #[test]
    fn counterproof_posted_pov_contested_payout() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
        let new_height = contest_height + ack_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let contested_payout_sigs =
            GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
                .expect("Failed to unpack signatures")
                .contested_payout;
        let signed_contested_payout_tx =
            game_graph.contested_payout.finalize(contested_payout_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: counter_proof_posted_state_with(
                    contest_height,
                    contest_height,
                    signatures.clone(),
                    BTreeMap::new(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: counter_proof_posted_state_with(
                    new_height,
                    contest_height,
                    signatures,
                    BTreeMap::new(),
                ),
                expected_duties: vec![GraphDuty::PublishContestedPayout {
                    signed_contested_payout_tx,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// Non-owner does not publish contested payout even after ack timelock.
    #[test]
    fn counterproof_posted_nonpov_no_contested_payout() {
        let cfg = test_graph_sm_cfg();
        let contest_height = LATER_BLOCK_HEIGHT;
        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
        let new_height = contest_height + ack_timelock + 1;

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: counter_proof_posted_state_with(
                    contest_height,
                    contest_height,
                    Default::default(),
                    BTreeMap::new(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: counter_proof_posted_state_with(
                    new_height,
                    contest_height,
                    Default::default(),
                    BTreeMap::new(),
                ),
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// Non-owner publishes slash after payout timelock expires.
    #[test]
    fn counterproof_posted_nonpov_slash() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let slash_sigs = GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
            .expect("Failed to unpack signatures")
            .slash;
        let signed_slash_tx = game_graph.slash.finalize(slash_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: counter_proof_posted_state_with(
                    contest_height,
                    contest_height,
                    signatures.clone(),
                    BTreeMap::new(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: counter_proof_posted_state_with(
                    new_height,
                    contest_height,
                    signatures,
                    BTreeMap::new(),
                ),
                expected_duties: vec![GraphDuty::PublishSlash { signed_slash_tx }],
                expected_signals: vec![],
            },
        );
    }

    /// Counterprover publishes ACK after nack timelock expires.
    #[test]
    fn counterproof_posted_nonpov_ack_viable_after_nack_timeout() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let graph_summary = test_graph_summary();
        let contest_height = LATER_BLOCK_HEIGHT;
        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());
        let counterproof_conf_height = contest_height + 1;
        let new_height = counterproof_conf_height + nack_timelock + 1;

        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)
            .expect("non-POV operator should map to watchtower slot");
        let counterproofs_and_confs = BTreeMap::from([(
            TEST_NONPOV_IDX,
            (
                graph_summary.counterproofs[watchtower_slot].counterproof,
                counterproof_conf_height,
            ),
        )]);

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let sigs = GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
            .expect("Failed to unpack signatures");
        let signed_counter_proof_ack_tx = game_graph.counterproofs[watchtower_slot]
            .counterproof_ack
            .clone()
            .finalize(sigs.watchtowers[watchtower_slot].counterproof_ack);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: counter_proof_posted_state_with(
                    contest_height,
                    contest_height,
                    signatures.clone(),
                    counterproofs_and_confs.clone(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: counter_proof_posted_state_with(
                    new_height,
                    contest_height,
                    signatures,
                    counterproofs_and_confs,
                ),
                expected_duties: vec![GraphDuty::PublishCounterProofAck {
                    signed_counter_proof_ack_tx,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// ACK not allowed exactly at nack timelock boundary.
    #[test]
    fn counterproof_posted_nonpov_ack_not_viable_at_nack_timeout_boundary() {
        let cfg = test_graph_sm_cfg();
        let graph_summary = test_graph_summary();
        let contest_height = LATER_BLOCK_HEIGHT;
        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());
        let counterproof_conf_height = contest_height + 1;
        let new_height = counterproof_conf_height + nack_timelock;
        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)
            .expect("non-POV operator should map to watchtower slot");

        let counterproofs_and_confs = BTreeMap::from([(
            TEST_NONPOV_IDX,
            (
                graph_summary.counterproofs[watchtower_slot].counterproof,
                counterproof_conf_height,
            ),
        )]);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: counter_proof_posted_state_with(
                    contest_height,
                    contest_height,
                    Default::default(),
                    counterproofs_and_confs.clone(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: counter_proof_posted_state_with(
                    new_height,
                    contest_height,
                    Default::default(),
                    counterproofs_and_confs,
                ),
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// ACK not allowed before nack timelock expires.
    #[test]
    fn counterproof_posted_nonpov_ack_not_viable_before_nack_timeout() {
        let cfg = test_graph_sm_cfg();
        let graph_summary = test_graph_summary();
        let contest_height = LATER_BLOCK_HEIGHT;
        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());
        let counterproof_conf_height = contest_height + 1;
        let new_height = counterproof_conf_height + nack_timelock - 1;
        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)
            .expect("non-POV operator should map to watchtower slot");

        let counterproofs_and_confs = BTreeMap::from([(
            TEST_NONPOV_IDX,
            (
                graph_summary.counterproofs[watchtower_slot].counterproof,
                counterproof_conf_height,
            ),
        )]);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: counter_proof_posted_state_with(
                    contest_height,
                    contest_height,
                    Default::default(),
                    counterproofs_and_confs.clone(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: counter_proof_posted_state_with(
                    new_height,
                    contest_height,
                    Default::default(),
                    counterproofs_and_confs,
                ),
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// Graph owner does not publish ACK even after nack timelock expires.
    #[test]
    fn counterproof_posted_owner_no_ack_before_ack_timeout_even_after_nack_timeout() {
        let cfg = test_graph_sm_cfg();
        let graph_summary = test_graph_summary();
        let contest_height = LATER_BLOCK_HEIGHT;
        let nack_timelock = u64::from(cfg.game_graph_params.nack_timelock.value());
        let ack_timelock = u64::from(cfg.game_graph_params.ack_timelock.value());
        let counterproof_conf_height = contest_height + 1;
        let new_height = counterproof_conf_height + nack_timelock + 1;
        assert!(new_height <= contest_height + ack_timelock);

        let watchtower_slot = watchtower_slot_for_operator(TEST_POV_IDX, TEST_NONPOV_IDX)
            .expect("non-POV operator should map to watchtower slot");
        let counterproofs_and_confs = BTreeMap::from([(
            TEST_NONPOV_IDX,
            (
                graph_summary.counterproofs[watchtower_slot].counterproof,
                counterproof_conf_height,
            ),
        )]);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: counter_proof_posted_state_with(
                    contest_height,
                    contest_height,
                    Default::default(),
                    counterproofs_and_confs.clone(),
                ),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: counter_proof_posted_state_with(
                    new_height,
                    contest_height,
                    Default::default(),
                    counterproofs_and_confs,
                ),
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// Rejects blocks at or below previously processed height.
    #[test]
    fn counterproof_posted_already_processed() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: counter_proof_posted_state(),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: LATER_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    // ===== Acked Tests =====

    /// Updates block height without triggering slash before payout timelock.
    #[test]
    fn acked_simple_update() {
        let cfg = test_graph_sm_cfg();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock;

        test_graph_transition(GraphTransition {
            from_state: acked_state_with(contest_height, contest_height, Default::default()),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: new_height,
            }),
            expected_state: acked_state_with(new_height, contest_height, Default::default()),
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Non-owner publishes slash after payout timelock expires in Acked state.
    #[test]
    fn acked_nonpov_payout_timeout_triggers_slash() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock + 1;

        let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());
        let signatures = mock_game_signatures(&game_graph);
        let slash_sigs = GameFunctor::unpack(signatures.clone(), ctx.watchtower_pubkeys().len())
            .expect("Failed to unpack signatures")
            .slash;
        let signed_slash_tx = game_graph.slash.finalize(slash_sigs);

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: acked_state_with(contest_height, contest_height, signatures.clone()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: acked_state_with(new_height, contest_height, signatures),
                expected_duties: vec![GraphDuty::PublishSlash { signed_slash_tx }],
                expected_signals: vec![],
            },
        );
    }

    /// Graph owner does not slash themselves even after payout timelock.
    #[test]
    fn acked_pov_payout_timeout_no_slash() {
        let cfg = test_graph_sm_cfg();
        let contest_height = LATER_BLOCK_HEIGHT;
        let payout_timelock = u64::from(cfg.game_graph_params.contested_payout_timelock.value());
        let new_height = contest_height + payout_timelock + 1;

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: acked_state_with(contest_height, contest_height, Default::default()),
                event: GraphEvent::NewBlock(NewBlockEvent {
                    block_height: new_height,
                }),
                expected_state: acked_state_with(new_height, contest_height, Default::default()),
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    /// Rejects blocks at or below previously processed height.
    #[test]
    fn acked_already_processed() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: acked_state(),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: LATER_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    /// Tests that Assigned state reverts to GraphSigned when fulfillment deadline is reached
    #[test]
    fn test_new_block_reverts_assigned_to_graph_signed_when_deadline_reached() {
        let deadline = INITIAL_BLOCK_HEIGHT + 10;

        test_graph_transition(GraphTransition {
            from_state: assigned_state(TEST_POV_IDX, deadline, test_recipient_desc(1)),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: deadline,
            }),
            expected_state: GraphState::GraphSigned {
                last_block_height: deadline,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                agg_nonces: None,
                signatures: Default::default(),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Tests that Assigned state stays in Assigned when deadline has not expired
    #[test]
    fn test_new_block_keeps_assigned_when_deadline_not_exceeded() {
        let deadline = LATER_BLOCK_HEIGHT;
        let block_height_before_deadline = deadline - 1;

        test_graph_transition(GraphTransition {
            from_state: assigned_state(TEST_POV_IDX, deadline, test_recipient_desc(1)),
            event: GraphEvent::NewBlock(NewBlockEvent {
                block_height: block_height_before_deadline,
            }),
            expected_state: GraphState::Assigned {
                last_block_height: block_height_before_deadline,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                signatures: Default::default(),
                assignee: TEST_POV_IDX,
                deadline,
                recipient_desc: test_recipient_desc(1),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }
}
