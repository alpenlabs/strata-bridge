//! Unit Tests for process_nonce_received
#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, num::NonZero, sync::Arc};

    use musig2::{AggNonce, PubNonce};
    use strata_bridge_primitives::types::OperatorIdx;
    use strata_bridge_test_utils::{
        bitcoin::generate_txid,
        musig2::generate_pubnonce,
    };
    use strata_bridge_tx_graph2::game_graph::{DepositParams, GameGraph};

    use crate::{
        graph::{
            config::GraphSMCfg,
            duties::GraphDuty,
            errors::GSMError,
            events::{GraphEvent, GraphNonceReceivedEvent},
            machine::generate_game_graph,
            state::GraphState,
            tests::{
                GraphInvalidTransition, INITIAL_BLOCK_HEIGHT, TEST_DEPOSIT_IDX, TEST_POV_IDX,
                create_sm, get_state, test_graph_invalid_transition, test_graph_sm_cfg,
                test_sm_ctx,
            },
        },
        signals::GraphSignal,
        testing::transition::{Transition, test_transition},
    };

    fn setup_graph(cfg: &Arc<GraphSMCfg>) -> (DepositParams, GameGraph, usize) {
        let ctx = test_sm_ctx();
        let deposit_params = DepositParams {
            game_index: NonZero::new(1).expect("nonzero game index"),
            claim_funds: Default::default(),
            deposit_outpoint: ctx.deposit_outpoint(),
        };
        let graph = generate_game_graph(cfg, &ctx, deposit_params);
        let nonce_count = graph.musig_signing_info().pack().len();

        (deposit_params, graph, nonce_count)
    }

    fn make_nonce_bundle(nonce_count: usize) -> Vec<PubNonce> {
        (0..nonce_count).map(|_| generate_pubnonce()).collect()
    }

    fn make_pubnonces_map(
        operator_count: usize,
        nonce_count: usize,
    ) -> BTreeMap<OperatorIdx, Vec<PubNonce>> {
        (0..operator_count)
            .map(|idx| (idx as OperatorIdx, make_nonce_bundle(nonce_count)))
            .collect()
    }

    fn operator_table_cardinality() -> usize {
        test_sm_ctx().operator_table().cardinality()
    }

    #[test]
    fn test_process_nonce_received_partial_collection() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph, nonce_count) = setup_graph(&cfg);
        let graph_summary = graph.summarize();

        let state = GraphState::AdaptorsVerified {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary: graph_summary.clone(),
            pubnonces: BTreeMap::new(),
        };

        let nonces = make_nonce_bundle(nonce_count);
        let mut expected_pubnonces = BTreeMap::new();
        expected_pubnonces.insert(TEST_POV_IDX, nonces.clone());

        test_transition(
            create_sm,
            get_state,
            cfg,
            Transition {
                from_state: state,
                event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                    operator_idx: TEST_POV_IDX,
                    nonces,
                }),
                expected_state: GraphState::AdaptorsVerified {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    graph_data: deposit_params,
                    graph_summary,
                    pubnonces: expected_pubnonces,
                },
                expected_duties: vec![],
                expected_signals: Vec::<GraphSignal>::new(),
            },
        );
    }

    #[test]
    fn test_process_nonce_received_all_collected() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph, nonce_count) = setup_graph(&cfg);
        let graph_summary = graph.summarize();
        let operator_count = operator_table_cardinality();

        let all_nonces = make_pubnonces_map(operator_count, nonce_count);
        let (&incoming_idx, incoming_nonces) =
            all_nonces.iter().last().expect("nonces map is empty");
        let mut initial_nonces = all_nonces.clone();
        initial_nonces.remove(&incoming_idx);
        let incoming_nonces = incoming_nonces.clone();

        let agg_nonces: Vec<_> = (0..nonce_count)
            .map(|nonce_idx| {
                let nonces_for_agg: Vec<_> = all_nonces
                    .values()
                    .map(|nonces| nonces[nonce_idx].clone())
                    .collect();
                AggNonce::sum(nonces_for_agg)
            })
            .collect();

        let signing_info = graph.musig_signing_info().pack();
        let (graph_tweaks, sighashes): (Vec<_>, Vec<_>) = signing_info
            .iter()
            .map(|info| (info.tweak, info.sighash))
            .unzip();
        let graph_inpoints = graph.musig_inpoints().pack();
        let claim_txid = graph.claim.as_ref().compute_txid();

        let state = GraphState::AdaptorsVerified {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary: graph_summary.clone(),
            pubnonces: initial_nonces,
        };

        let expected_state = GraphState::NoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary,
            agg_nonces: agg_nonces.clone(),
            partial_signatures: BTreeMap::new(),
        };

        let duplicate_state = expected_state.clone();

        test_transition(
            create_sm,
            get_state,
            cfg,
            Transition {
                from_state: state,
                event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                    operator_idx: incoming_idx,
                    nonces: incoming_nonces,
                }),
                expected_state,
                expected_duties: vec![GraphDuty::PublishGraphPartials {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    operator_idx: TEST_POV_IDX,
                    agg_nonces,
                    sighashes,
                    graph_inpoints,
                    graph_tweaks,
                    claim_txid,
                }],
                expected_signals: Vec::<GraphSignal>::new(),
            },
        );

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: duplicate_state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                nonces: make_nonce_bundle(nonce_count),
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_process_nonce_received_duplicate_operator() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph, nonce_count) = setup_graph(&cfg);
        let graph_summary = graph.summarize();

        let mut pubnonces = BTreeMap::new();
        let nonces = make_nonce_bundle(nonce_count);
        pubnonces.insert(TEST_POV_IDX, nonces.clone());

        let state = GraphState::AdaptorsVerified {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary,
            pubnonces,
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                nonces,
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_invalid_operator_idx_in_process_nonce_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph, nonce_count) = setup_graph(&cfg);
        let graph_summary = graph.summarize();

        let state = GraphState::AdaptorsVerified {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary,
            pubnonces: BTreeMap::new(),
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: u32::MAX,
                nonces: make_nonce_bundle(nonce_count),
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_invalid_nonce_bundle_in_process_nonce_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph, _nonce_count) = setup_graph(&cfg);
        let graph_summary = graph.summarize();

        let state = GraphState::AdaptorsVerified {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary,
            pubnonces: BTreeMap::new(),
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                nonces: vec![],
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_invalid_process_nonce_received_from_withdrawn() {
        let cfg = test_graph_sm_cfg();
        let (_deposit_params, _graph, nonce_count) = setup_graph(&cfg);

        let state = GraphState::Withdrawn {
            payout_txid: generate_txid(),
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                nonces: make_nonce_bundle(nonce_count),
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
