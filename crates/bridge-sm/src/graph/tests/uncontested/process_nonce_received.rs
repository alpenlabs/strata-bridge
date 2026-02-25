//! Unit Tests for process_nonce_received
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{GraphEvent, GraphNonceReceivedEvent},
            state::GraphState,
            tests::{
                GraphInvalidTransition, GraphTransition, INITIAL_BLOCK_HEIGHT, TEST_POV_IDX,
                create_sm, get_state, mock_states::adaptors_verified_state, test_graph_data,
                test_graph_invalid_transition, test_graph_sm_cfg, test_graph_transition,
                utils::build_nonce_context,
            },
        },
        signals::GraphSignal,
        testing::transition::EventSequence,
    };

    #[test]
    fn test_process_nonce_received_partial_collection() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = adaptors_verified_state(deposit_params, graph_summary.clone());

        let operator_nonces = nonce_ctx
            .pubnonces
            .get(&TEST_POV_IDX)
            .expect("operator nonces missing")
            .clone();

        let mut expected_pubnonces = BTreeMap::new();
        expected_pubnonces.insert(TEST_POV_IDX, operator_nonces.clone());

        test_graph_transition(GraphTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                pubnonces: operator_nonces,
            }),
            expected_state: GraphState::AdaptorsVerified {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: deposit_params,
                graph_summary,
                pubnonces: expected_pubnonces,
            },
            expected_duties: vec![],
            expected_signals: Vec::<GraphSignal>::new(),
        });
    }

    #[test]
    fn test_process_nonce_received_all_collected() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = adaptors_verified_state(deposit_params, graph_summary);

        let sm = create_sm(state);
        let mut seq = EventSequence::new(sm, get_state);

        for signer in &nonce_ctx.signers {
            let nonces = nonce_ctx
                .pubnonces
                .get(&signer.operator_idx())
                .expect("operator nonces missing")
                .clone();
            seq.process(
                cfg.clone(),
                GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                    operator_idx: signer.operator_idx(),
                    pubnonces: nonces,
                }),
            );
        }

        seq.assert_no_errors();
        assert!(matches!(seq.state(), GraphState::NoncesCollected { .. }));
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [GraphDuty::PublishGraphPartials { .. }]
            ),
            "Expected exactly 1 PublishGraphPartials duty to be emitted"
        );
        assert!(seq.all_signals().is_empty());
    }

    #[test]
    fn test_duplicate_process_nonce_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let operator_nonces = nonce_ctx
            .pubnonces
            .get(&TEST_POV_IDX)
            .expect("operator nonces missing")
            .clone();

        let mut pubnonces = BTreeMap::new();
        pubnonces.insert(TEST_POV_IDX, operator_nonces.clone());

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
                pubnonces: operator_nonces,
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_invalid_operator_idx_in_process_nonce_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = adaptors_verified_state(deposit_params, graph_summary);

        let operator_nonces = nonce_ctx
            .pubnonces
            .get(&TEST_POV_IDX)
            .expect("operator nonces missing")
            .clone();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: u32::MAX,
                pubnonces: operator_nonces,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_invalid_nonce_bundle_in_process_nonce_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = adaptors_verified_state(deposit_params, graph_summary);

        let mut operator_nonces = nonce_ctx
            .pubnonces
            .get(&TEST_POV_IDX)
            .expect("operator nonces missing")
            .clone();
        operator_nonces.pop();

        // Empty nonces
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state.clone(),
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                pubnonces: vec![],
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });

        // Missing one nonce
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                pubnonces: operator_nonces,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_nonce_received_in_nonces_collected_state() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let operator_nonces = nonce_ctx
            .pubnonces
            .get(&TEST_POV_IDX)
            .expect("operator nonces missing")
            .clone();

        let state = GraphState::NoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary,
            pubnonces: nonce_ctx.pubnonces.clone(),
            agg_nonces: nonce_ctx.agg_nonces.clone(),
            partial_signatures: BTreeMap::new(),
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::NonceReceived(GraphNonceReceivedEvent {
                operator_idx: TEST_POV_IDX,
                pubnonces: operator_nonces,
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }
}
