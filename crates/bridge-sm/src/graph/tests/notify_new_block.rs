//! Unit Tests for notify_new_block in Claimed state
#[cfg(test)]
mod tests {
    use musig2::secp256k1::schnorr::Signature;
    use strata_bridge_test_utils::{bitcoin::generate_txid, prelude::generate_signature};
    use strata_bridge_tx_graph2::{game_graph::GameGraph, musig_functor::GameFunctor};

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{GraphEvent, NewBlockEvent},
            machine::{GraphSM, generate_game_graph},
            state::GraphState,
            tests::{
                CLAIM_BLOCK_HEIGHT, CONTEST_TIMELOCK_BLOCKS, GraphInvalidTransition,
                GraphTransition, INITIAL_BLOCK_HEIGHT, create_sm, get_state, test_deposit_params,
                test_graph_invalid_transition, test_graph_sm_cfg, test_graph_sm_ctx,
                test_graph_summary, test_graph_transition,
            },
        },
        testing::test_transition,
    };

    /// Creates a packed vector of mock signatures whose layout matches
    /// the game graph's signing info structure.
    fn mock_game_signatures(game_graph: &GameGraph) -> Vec<Signature> {
        game_graph
            .musig_signing_info()
            .map(|_| generate_signature())
            .pack()
    }

    /// Builds a mock `Claimed` state with the given parameters.
    fn claimed_state(
        last_block_height: u64,
        fulfillment_txid: bitcoin::Txid,
        signatures: Vec<Signature>,
    ) -> GraphState {
        GraphState::Claimed {
            last_block_height,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures,
            fulfillment_txid: Some(fulfillment_txid),
            fulfillment_block_height: Some(140),
            claim_block_height: CLAIM_BLOCK_HEIGHT,
        }
    }

    // TODO:(@MdTeach): Add proptest that asserts `NewBlock` events with
    // `block_height <= last_processed_block_height` are always rejected,
    // and otherwise `last_block_height` is updated to the new block height.

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
            GameFunctor::unpack(signatures.clone(), cfg.watchtower_pubkeys.len())
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
}
