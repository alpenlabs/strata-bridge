//! Unit Tests for process_partial_received
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        graph::{
            errors::GSMError,
            events::{GraphEvent, GraphPartialsReceivedEvent},
            state::GraphState,
            tests::{
                GraphInvalidTransition, INITIAL_BLOCK_HEIGHT, TEST_POV_IDX, create_sm, get_state,
                mock_states::nonces_collected_state,
                test_graph_data, test_graph_invalid_transition, test_graph_sm_cfg,
                utils::{build_nonce_context, build_partial_signatures},
            },
        },
        signals::{GraphSignal, GraphToDeposit},
        testing::transition::EventSequence,
    };

    #[test]
    fn test_process_partial_received_partial_collection() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();
        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = nonces_collected_state(&nonce_ctx, deposit_params, graph_summary.clone());

        let partial_sigs_map = build_partial_signatures(
            &nonce_ctx.signers,
            &nonce_ctx.key_agg_ctxs,
            &nonce_ctx.agg_nonces,
            &nonce_ctx.signing_infos,
            0,
        );
        let operator_partials = partial_sigs_map
            .get(&TEST_POV_IDX)
            .expect("operator partial signatures missing")
            .clone();

        let mut expected_partials = BTreeMap::new();
        expected_partials.insert(TEST_POV_IDX, operator_partials.clone());

        let sm = create_sm(state);
        let mut seq = EventSequence::new(sm, get_state);
        seq.process(
            cfg,
            GraphEvent::PartialsReceived(GraphPartialsReceivedEvent {
                operator_idx: TEST_POV_IDX,
                partial_signatures: operator_partials,
            }),
        );

        seq.assert_no_errors();
        seq.assert_final_state(&GraphState::NoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary,
            pubnonces: nonce_ctx.pubnonces.clone(),
            agg_nonces: nonce_ctx.agg_nonces.clone(),
            partial_signatures: expected_partials,
        });
        assert!(seq.all_duties().is_empty());
        assert!(seq.all_signals().is_empty());
    }

    #[test]
    fn test_process_partial_received_all_collected() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = nonces_collected_state(&nonce_ctx, deposit_params, graph_summary);

        let partial_sigs_map = build_partial_signatures(
            &nonce_ctx.signers,
            &nonce_ctx.key_agg_ctxs,
            &nonce_ctx.agg_nonces,
            &nonce_ctx.signing_infos,
            0,
        );

        let sm = create_sm(state);
        let mut seq = EventSequence::new(sm, get_state);

        for signer in &nonce_ctx.signers {
            let sigs = partial_sigs_map
                .get(&signer.operator_idx())
                .expect("operator partial signatures missing")
                .clone();
            seq.process(
                cfg.clone(),
                GraphEvent::PartialsReceived(GraphPartialsReceivedEvent {
                    operator_idx: signer.operator_idx(),
                    partial_signatures: sigs,
                }),
            );
        }

        seq.assert_no_errors();

        assert!(matches!(seq.state(), GraphState::GraphSigned { .. }));
        if let GraphState::GraphSigned { signatures, .. } = seq.state() {
            assert_eq!(signatures.len(), nonce_ctx.signing_infos.len());
        }

        assert!(seq.all_duties().is_empty());
        assert!(matches!(
            seq.all_signals().as_slice(),
            [GraphSignal::ToDeposit(
                GraphToDeposit::GraphAvailable { .. }
            )]
        ));
    }

    #[test]
    fn test_invalid_process_partial_received_sequence() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = nonces_collected_state(&nonce_ctx, deposit_params, graph_summary);

        let invalid_partials = build_partial_signatures(
            &nonce_ctx.signers,
            &nonce_ctx.key_agg_ctxs,
            &nonce_ctx.agg_nonces,
            &nonce_ctx.signing_infos,
            1,
        );

        let sm = create_sm(state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        for signer in &nonce_ctx.signers {
            let sigs = invalid_partials
                .get(&signer.operator_idx())
                .expect("operator partial signatures missing")
                .clone();
            seq.process(
                cfg.clone(),
                GraphEvent::PartialsReceived(GraphPartialsReceivedEvent {
                    operator_idx: signer.operator_idx(),
                    partial_signatures: sigs,
                }),
            );
        }

        seq.assert_final_state(&state);

        let errors = seq.all_errors();
        assert_eq!(
            errors.len(),
            nonce_ctx.signers.len(),
            "Expected {} errors for invalid partial signatures, got {}",
            nonce_ctx.signers.len(),
            errors.len()
        );
        errors.iter().for_each(|err| {
            assert!(
                matches!(err, GSMError::Rejected { .. }),
                "Expected Rejected error, got {:?}",
                err
            );
        });
    }

    #[test]
    fn test_duplicate_process_partial_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let partial_sigs_map = build_partial_signatures(
            &nonce_ctx.signers,
            &nonce_ctx.key_agg_ctxs,
            &nonce_ctx.agg_nonces,
            &nonce_ctx.signing_infos,
            0,
        );
        let operator_partials = partial_sigs_map
            .get(&TEST_POV_IDX)
            .expect("operator partial signatures missing")
            .clone();

        let mut partial_signatures = BTreeMap::new();
        partial_signatures.insert(TEST_POV_IDX, operator_partials.clone());

        let state = GraphState::NoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary,
            pubnonces: nonce_ctx.pubnonces,
            agg_nonces: nonce_ctx.agg_nonces,
            partial_signatures,
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PartialsReceived(GraphPartialsReceivedEvent {
                operator_idx: TEST_POV_IDX,
                partial_signatures: operator_partials,
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_invalid_operator_idx_in_process_partial_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = nonces_collected_state(&nonce_ctx, deposit_params, graph_summary);

        let partial_sigs_map = build_partial_signatures(
            &nonce_ctx.signers,
            &nonce_ctx.key_agg_ctxs,
            &nonce_ctx.agg_nonces,
            &nonce_ctx.signing_infos,
            0,
        );
        let operator_partials = partial_sigs_map
            .get(&TEST_POV_IDX)
            .expect("operator partial signatures missing")
            .clone();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PartialsReceived(GraphPartialsReceivedEvent {
                operator_idx: u32::MAX,
                partial_signatures: operator_partials,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_invalid_partial_bundle_in_process_partial_received() {
        let cfg = test_graph_sm_cfg();
        let (deposit_params, graph) = test_graph_data(&cfg);
        let graph_summary = graph.summarize();

        let nonce_ctx = build_nonce_context(graph.musig_signing_info().pack());
        let state = nonces_collected_state(&nonce_ctx, deposit_params, graph_summary);

        let partial_sigs_map = build_partial_signatures(
            &nonce_ctx.signers,
            &nonce_ctx.key_agg_ctxs,
            &nonce_ctx.agg_nonces,
            &nonce_ctx.signing_infos,
            0,
        );
        let mut operator_partials = partial_sigs_map
            .get(&TEST_POV_IDX)
            .expect("operator partial signatures missing")
            .clone();
        operator_partials.pop();

        // Empty partials
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state.clone(),
            event: GraphEvent::PartialsReceived(GraphPartialsReceivedEvent {
                operator_idx: TEST_POV_IDX,
                partial_signatures: vec![],
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });

        // Missing one partials
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PartialsReceived(GraphPartialsReceivedEvent {
                operator_idx: TEST_POV_IDX,
                partial_signatures: operator_partials,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }
}
