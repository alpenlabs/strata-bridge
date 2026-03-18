//! Unit Tests for notify_new_block in Claimed state
#[cfg(test)]
mod tests {
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
                GraphTransition, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT, create_sm, get_state,
                mock_game_signatures,
                mock_states::{
                    bridge_proof_timedout_state_with, claimed_state, contested_state_with,
                },
                test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
                test_graph_sm_ctx, test_graph_transition,
            },
        },
        testing::test_transition,
    };

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
}
