//! Unit Tests for process_partial_received
#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, num::NonZero, sync::Arc};

    use musig2::{AggNonce, KeyAggContext, PartialSignature, PubNonce};
    use strata_bridge_connectors2::SigningInfo;
    use strata_bridge_primitives::{key_agg::create_agg_ctx, types::OperatorIdx};
    use strata_bridge_tx_graph2::game_graph::{DepositParams, GameGraph, GameGraphSummary};

    use crate::{
        graph::{
            config::GraphSMCfg,
            errors::GSMError,
            events::{GraphEvent, GraphPartialReceivedEvent},
            machine::generate_game_graph,
            state::GraphState,
            tests::{
                GraphInvalidTransition, INITIAL_BLOCK_HEIGHT, TEST_POV_IDX, create_sm, get_state,
                test_graph_invalid_transition, test_graph_sm_cfg, test_sm_ctx,
            },
        },
        signals::GraphSignal,
        testing::{
            signer::{TestMusigSigner, test_operator_signers},
            transition::{EventSequence, Transition, test_transition},
        },
    };

    struct NonceContext {
        deposit_params: DepositParams,
        graph_summary: GameGraphSummary,
        signing_infos: Vec<SigningInfo>,
        signers: Vec<TestMusigSigner>,
        key_agg_ctxs: Vec<KeyAggContext>,
        pubnonces: BTreeMap<OperatorIdx, Vec<PubNonce>>,
        agg_nonces: Vec<AggNonce>,
    }

    fn setup_graph(cfg: &Arc<GraphSMCfg>) -> (DepositParams, GameGraph, Vec<SigningInfo>) {
        let ctx = test_sm_ctx();
        let deposit_params = DepositParams {
            game_index: NonZero::new(1).expect("nonzero game index"),
            claim_funds: Default::default(),
            deposit_outpoint: ctx.deposit_outpoint(),
        };
        let graph = generate_game_graph(cfg, &ctx, deposit_params);
        let signing_infos = graph.musig_signing_info().pack();

        (deposit_params, graph, signing_infos)
    }

    fn build_key_agg_ctxs(signing_infos: &[SigningInfo]) -> Vec<KeyAggContext> {
        let btc_keys: Vec<_> = test_sm_ctx().operator_table().btc_keys().into_iter().collect();
        signing_infos
            .iter()
            .map(|info| {
                create_agg_ctx(btc_keys.iter().copied(), &info.tweak)
                    .expect("must be able to create key aggregation context")
            })
            .collect()
    }

    fn build_pubnonces(
        signers: &[TestMusigSigner],
        key_agg_ctxs: &[KeyAggContext],
    ) -> BTreeMap<OperatorIdx, Vec<PubNonce>> {
        let agg_pubkeys: Vec<_> = key_agg_ctxs
            .iter()
            .map(|ctx| ctx.aggregated_pubkey())
            .collect();

        signers
            .iter()
            .map(|signer| {
                let nonces = agg_pubkeys
                    .iter()
                    .enumerate()
                    .map(|(idx, agg_pubkey)| signer.pubnonce(*agg_pubkey, idx as u64))
                    .collect();
                (signer.operator_idx(), nonces)
            })
            .collect()
    }

    fn build_agg_nonces(
        pubnonces: &BTreeMap<OperatorIdx, Vec<PubNonce>>,
        nonce_count: usize,
    ) -> Vec<AggNonce> {
        (0..nonce_count)
            .map(|nonce_idx| {
                AggNonce::sum(
                    pubnonces
                        .values()
                        .map(|nonces| nonces[nonce_idx].clone()),
                )
            })
            .collect()
    }

    fn build_partial_signatures(
        signers: &[TestMusigSigner],
        key_agg_ctxs: &[KeyAggContext],
        agg_nonces: &[AggNonce],
        signing_infos: &[SigningInfo],
        nonce_offset: u64,
    ) -> BTreeMap<OperatorIdx, Vec<PartialSignature>> {
        signers
            .iter()
            .map(|signer| {
                let sigs = signing_infos
                    .iter()
                    .enumerate()
                    .map(|(idx, info)| {
                        let nonce_counter = idx as u64 + nonce_offset;
                        signer.sign(
                            &key_agg_ctxs[idx],
                            nonce_counter,
                            &agg_nonces[idx],
                            info.sighash,
                        )
                    })
                    .collect();
                (signer.operator_idx(), sigs)
            })
            .collect()
    }

    fn build_nonce_context(cfg: &Arc<GraphSMCfg>) -> NonceContext {
        let (deposit_params, graph, signing_infos) = setup_graph(cfg);
        let graph_summary = graph.summarize();
        let signers = test_operator_signers(test_sm_ctx().operator_table().cardinality());
        let key_agg_ctxs = build_key_agg_ctxs(&signing_infos);
        let pubnonces = build_pubnonces(&signers, &key_agg_ctxs);
        let agg_nonces = build_agg_nonces(&pubnonces, signing_infos.len());

        NonceContext {
            deposit_params,
            graph_summary,
            signing_infos,
            signers,
            key_agg_ctxs,
            pubnonces,
            agg_nonces,
        }
    }

    fn nonces_collected_state(ctx: &NonceContext) -> GraphState {
        GraphState::NoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: ctx.deposit_params,
            graph_summary: ctx.graph_summary.clone(),
            pubnonces: ctx.pubnonces.clone(),
            agg_nonces: ctx.agg_nonces.clone(),
            partial_signatures: BTreeMap::new(),
        }
    }

    #[test]
    fn test_process_partial_received_partial_collection() {
        let cfg = test_graph_sm_cfg();
        let ctx = build_nonce_context(&cfg);
        let state = nonces_collected_state(&ctx);

        let partial_sigs_map = build_partial_signatures(
            &ctx.signers,
            &ctx.key_agg_ctxs,
            &ctx.agg_nonces,
            &ctx.signing_infos,
            0,
        );
        let operator_partials = partial_sigs_map
            .get(&TEST_POV_IDX)
            .expect("operator partial signatures missing")
            .clone();

        let mut expected_partials = BTreeMap::new();
        expected_partials.insert(TEST_POV_IDX, operator_partials.clone());

        test_transition(
            create_sm,
            get_state,
            cfg,
            Transition {
                from_state: state,
                event: GraphEvent::PartialReceived(GraphPartialReceivedEvent {
                    operator_idx: TEST_POV_IDX,
                    partial_sigs: operator_partials,
                }),
                expected_state: GraphState::NoncesCollected {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    graph_data: ctx.deposit_params,
                    graph_summary: ctx.graph_summary.clone(),
                    pubnonces: ctx.pubnonces.clone(),
                    agg_nonces: ctx.agg_nonces.clone(),
                    partial_signatures: expected_partials,
                },
                expected_duties: vec![],
                expected_signals: Vec::<GraphSignal>::new(),
            },
        );
    }

    #[test]
    fn test_process_partial_received_all_collected() {
        let cfg = test_graph_sm_cfg();
        let ctx = build_nonce_context(&cfg);
        let state = nonces_collected_state(&ctx);

        let partial_sigs_map = build_partial_signatures(
            &ctx.signers,
            &ctx.key_agg_ctxs,
            &ctx.agg_nonces,
            &ctx.signing_infos,
            0,
        );

        let sm = create_sm(state);
        let mut seq = EventSequence::new(sm, get_state);

        for signer in &ctx.signers {
            let sigs = partial_sigs_map
                .get(&signer.operator_idx())
                .expect("operator partial signatures missing")
                .clone();
            seq.process(
                cfg.clone(),
                GraphEvent::PartialReceived(GraphPartialReceivedEvent {
                    operator_idx: signer.operator_idx(),
                    partial_sigs: sigs,
                }),
            );
        }

        seq.assert_no_errors();

        assert!(matches!(seq.state(), GraphState::GraphSigned { .. }));
        if let GraphState::GraphSigned { signatures, .. } = seq.state() {
            assert_eq!(signatures.len(), ctx.signing_infos.len());
        }

        assert!(seq.all_duties().is_empty());
        assert!(seq.all_signals().is_empty());
    }

    #[test]
    fn test_invalid_process_partial_received_sequence() {
        let cfg = test_graph_sm_cfg();
        let ctx = build_nonce_context(&cfg);
        let state = nonces_collected_state(&ctx);

        let invalid_partials = build_partial_signatures(
            &ctx.signers,
            &ctx.key_agg_ctxs,
            &ctx.agg_nonces,
            &ctx.signing_infos,
            1,
        );

        let sm = create_sm(state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        for signer in &ctx.signers {
            let sigs = invalid_partials
                .get(&signer.operator_idx())
                .expect("operator partial signatures missing")
                .clone();
            seq.process(
                cfg.clone(),
                GraphEvent::PartialReceived(GraphPartialReceivedEvent {
                    operator_idx: signer.operator_idx(),
                    partial_sigs: sigs,
                }),
            );
        }

        seq.assert_final_state(&state);

        let errors = seq.all_errors();
        assert_eq!(
            errors.len(),
            ctx.signers.len(),
            "Expected {} errors for invalid partial signatures, got {}",
            ctx.signers.len(),
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
        let ctx = build_nonce_context(&cfg);

        let partial_sigs_map = build_partial_signatures(
            &ctx.signers,
            &ctx.key_agg_ctxs,
            &ctx.agg_nonces,
            &ctx.signing_infos,
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
            graph_data: ctx.deposit_params,
            graph_summary: ctx.graph_summary,
            pubnonces: ctx.pubnonces,
            agg_nonces: ctx.agg_nonces,
            partial_signatures,
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PartialReceived(GraphPartialReceivedEvent {
                operator_idx: TEST_POV_IDX,
                partial_sigs: operator_partials,
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_invalid_operator_idx_in_process_partial_received() {
        let cfg = test_graph_sm_cfg();
        let ctx = build_nonce_context(&cfg);
        let state = nonces_collected_state(&ctx);

        let partial_sigs_map = build_partial_signatures(
            &ctx.signers,
            &ctx.key_agg_ctxs,
            &ctx.agg_nonces,
            &ctx.signing_infos,
            0,
        );
        let operator_partials = partial_sigs_map
            .get(&TEST_POV_IDX)
            .expect("operator partial signatures missing")
            .clone();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PartialReceived(GraphPartialReceivedEvent {
                operator_idx: u32::MAX,
                partial_sigs: operator_partials,
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_invalid_partial_bundle_in_process_partial_received() {
        let cfg = test_graph_sm_cfg();
        let ctx = build_nonce_context(&cfg);
        let state = nonces_collected_state(&ctx);

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PartialReceived(GraphPartialReceivedEvent {
                operator_idx: TEST_POV_IDX,
                partial_sigs: vec![],
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }
}
