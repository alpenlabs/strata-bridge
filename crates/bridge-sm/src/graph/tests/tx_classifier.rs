//! Unit tests for the [`TxClassifier`] implementation on [`GraphSM`].
//!
//! These are exhaustive unit tests (not proptests) because classify_tx's
//! behavior depends on the state *variant*, not the field values within each
//! variant. Enumerating every variant gives guaranteed exhaustive coverage.

#[cfg(test)]
mod tests {
    use bitcoin::{
        OutPoint,
        hashes::{Hash, sha256},
    };
    use strata_bridge_primitives::types::{GraphIdx, OperatorIdx};
    use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_txid};
    use strata_bridge_tx_graph::{
        game_graph::{CounterproofGraphSummary, GameGraphSummary},
        transactions::prelude::CounterproofTx,
    };

    use crate::{
        graph::{
            context::GraphSMCtx,
            machine::GraphSM,
            state::GraphState,
            tests::{mock_states::*, *},
        },
        testing::fixtures::{TEST_DEPOSIT_IDX, test_operator_table},
        tx_classifier::TxClassifier,
    };

    /// Generates a graph summary with the specified number of counterproofs, along with the
    /// corresponding counterproof and ack transactions in full that reference the summary's
    /// counterproofs.
    fn test_counterproof_summary_with_watchtowers(
        watchtower_count: usize,
    ) -> (GameGraphSummary, Vec<Transaction>, Vec<Transaction>) {
        let mut summary = test_graph_summary();
        let counterproof_txs = (0..watchtower_count)
            .map(|idx| {
                generate_spending_tx(
                    OutPoint {
                        txid: generate_txid(),
                        vout: 10 + idx as u32,
                    },
                    &[],
                )
            })
            .collect::<Vec<_>>();
        let counterproof_ack_txs = (0..watchtower_count)
            .map(|idx| {
                generate_spending_tx(
                    OutPoint {
                        txid: generate_txid(),
                        vout: 20 + idx as u32,
                    },
                    &[],
                )
            })
            .collect::<Vec<_>>();
        summary.counterproofs = counterproof_txs
            .iter()
            .zip(&counterproof_ack_txs)
            .map(|(counterproof_tx, ack_tx)| CounterproofGraphSummary {
                counterproof: counterproof_tx.compute_txid(),
                counterproof_ack: ack_tx.compute_txid(),
            })
            .collect();

        (summary, counterproof_txs, counterproof_ack_txs)
    }

    fn replace_graph_summary(mut state: GraphState, graph_summary: GameGraphSummary) -> GraphState {
        match &mut state {
            GraphState::Contested {
                graph_summary: state_summary,
                ..
            }
            | GraphState::BridgeProofPosted {
                graph_summary: state_summary,
                ..
            }
            | GraphState::CounterProofPosted {
                graph_summary: state_summary,
                ..
            } => *state_summary = graph_summary,
            _ => panic!("test state must carry a graph summary"),
        }

        state
    }

    fn create_sm_with_owner_and_pov(
        state: GraphState,
        graph_owner_idx: OperatorIdx,
        pov_idx: OperatorIdx,
    ) -> GraphSM {
        GraphSM {
            context: GraphSMCtx {
                graph_idx: GraphIdx {
                    deposit: TEST_DEPOSIT_IDX,
                    operator: graph_owner_idx,
                },
                deposit_outpoint: OutPoint::default(),
                stake_outpoint: OutPoint::default(),
                unstaking_image: sha256::Hash::all_zeros(),
                operator_table: test_operator_table(N_TEST_OPERATORS, pov_idx),
            },
            state,
        }
    }

    /// Asserts that the counterproof, ACK and NACK transactions for the specified counterproof
    /// slot are all attributed to the expected operator index.
    fn assert_counterproof_graph_attribution(
        graph_owner_idx: OperatorIdx,
        pov_idx: OperatorIdx,
        counterproof_slot: usize,
        expected_operator_idx: OperatorIdx,
    ) {
        let cfg = test_graph_sm_cfg();
        let (graph_summary, counterproof_txs, counterproof_ack_txs) =
            test_counterproof_summary_with_watchtowers(N_TEST_OPERATORS - 1);

        let contested_sm = create_sm_with_owner_and_pov(
            replace_graph_summary(contested_state(), graph_summary.clone()),
            graph_owner_idx,
            pov_idx,
        );
        let counterproof_result = contested_sm.classify_tx(
            &cfg,
            &counterproof_txs[counterproof_slot],
            LATER_BLOCK_HEIGHT,
        );
        match counterproof_result {
            Some(GraphEvent::CounterProofConfirmed(event)) => {
                assert_eq!(event.counterprover_idx, expected_operator_idx);
            }
            _ => panic!("expected Some(CounterProofConfirmed) but got {counterproof_result:?}"),
        }

        let counterproof_posted_sm = create_sm_with_owner_and_pov(
            replace_graph_summary(counter_proof_posted_state(), graph_summary),
            graph_owner_idx,
            pov_idx,
        );
        let ack_result = counterproof_posted_sm.classify_tx(
            &cfg,
            &counterproof_ack_txs[counterproof_slot],
            LATER_BLOCK_HEIGHT,
        );
        match ack_result {
            Some(GraphEvent::CounterProofAckConfirmed(event)) => {
                assert_eq!(event.counterprover_idx, expected_operator_idx);
            }
            _ => panic!("expected Some(CounterProofAckConfirmed) but got {ack_result:?}"),
        }

        let nack_tx = generate_spending_tx(
            OutPoint {
                txid: counterproof_txs[counterproof_slot].compute_txid(),
                vout: CounterproofTx::ACK_NACK_VOUT,
            },
            &[],
        );
        let nack_result = counterproof_posted_sm.classify_tx(&cfg, &nack_tx, LATER_BLOCK_HEIGHT);
        match nack_result {
            Some(GraphEvent::CounterProofNackConfirmed(event)) => {
                assert_eq!(event.counterprover_idx, expected_operator_idx);
            }
            _ => panic!("expected Some(CounterProofNackConfirmed) but got {nack_result:?}"),
        }
    }

    // --- Positive tests: classify_tx returns the correct event ---

    #[test]
    fn classify_tx_recognizes_claim() {
        let cfg = test_graph_sm_cfg();
        let claim_tx = TestGraphTxKind::Claim.into();
        for state in claim_detecting_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(&cfg, &claim_tx, LATER_BLOCK_HEIGHT);
            assert!(
                matches!(result, Some(GraphEvent::ClaimConfirmed(_))),
                "expected Some(ClaimConfirmed) but got {result:?}"
            );
        }
    }

    #[test]
    fn classify_tx_recognizes_fulfillment_in_assigned() {
        let cfg = test_graph_sm_cfg();
        let (_, _, nonce_ctx) = test_nonce_context();
        let sm = create_sm(assigned_state(
            &nonce_ctx,
            TEST_ASSIGNEE,
            LATER_BLOCK_HEIGHT + 15,
            test_recipient_desc(1),
        ));
        let result = sm.classify_tx(&cfg, &test_fulfillment_tx(), LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(GraphEvent::FulfillmentConfirmed(_))),
            "expected Some(FulfillmentConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_contest_in_claimed() {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(claimed_state(
            LATER_BLOCK_HEIGHT,
            generate_txid(),
            Default::default(),
        ));
        let result = sm.classify_tx(&cfg, &TestGraphTxKind::Contest.into(), LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(GraphEvent::ContestConfirmed(_))),
            "expected Some(ContestConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_bridge_proof_in_contested() {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(contested_state());
        let result = sm.classify_tx(&cfg, &test_bridge_proof_tx(), LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(GraphEvent::BridgeProofConfirmed(_))),
            "expected Some(BridgeProofConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_counterproof_in_contested_and_bridge_proof_posted() {
        let cfg = test_graph_sm_cfg();
        for state in counterproof_detecting_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(
                &cfg,
                &TestGraphTxKind::Counterproof.into(),
                LATER_BLOCK_HEIGHT,
            );
            assert!(
                matches!(result, Some(GraphEvent::CounterProofConfirmed(_))),
                "expected Some(CounterProofConfirmed) but got {result:?}"
            );
        }
    }

    #[test]
    fn classify_tx_recognizes_uncontested_payout() {
        let cfg = test_graph_sm_cfg();
        for state in uncontested_payout_detecting_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(
                &cfg,
                &TestGraphTxKind::UncontestedPayout.into(),
                LATER_BLOCK_HEIGHT,
            );
            assert!(
                matches!(result, Some(GraphEvent::PayoutConfirmed(_))),
                "expected Some(PayoutConfirmed) but got {result:?}"
            );
        }
    }

    #[test]
    fn classify_tx_recognizes_contested_payout() {
        let cfg = test_graph_sm_cfg();
        for state in contested_payout_detecting_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(
                &cfg,
                &TestGraphTxKind::ContestedPayout.into(),
                LATER_BLOCK_HEIGHT,
            );
            assert!(
                matches!(result, Some(GraphEvent::PayoutConfirmed(_))),
                "expected Some(PayoutConfirmed) but got {result:?}"
            );
        }
    }

    #[test]
    fn classify_tx_recognizes_bridge_proof_timeout() {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(bridge_proof_timedout_state());
        let result = sm.classify_tx(
            &cfg,
            &TestGraphTxKind::BridgeProofTimeout.into(),
            LATER_BLOCK_HEIGHT,
        );
        assert!(
            matches!(result, Some(GraphEvent::BridgeProofTimeoutConfirmed(_))),
            "expected Some(BridgeProofTimeoutConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_counterproof_ack() {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(counter_proof_posted_state());
        let result = sm.classify_tx(
            &cfg,
            &TestGraphTxKind::CounterproofAck.into(),
            LATER_BLOCK_HEIGHT,
        );
        assert!(
            matches!(result, Some(GraphEvent::CounterProofAckConfirmed(_))),
            "expected Some(CounterProofAckConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_counterproof_nack() {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(counter_proof_posted_state());
        let result = sm.classify_tx(&cfg, &test_counterproof_nack_tx(), LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(GraphEvent::CounterProofNackConfirmed(_))),
            "expected Some(CounterProofNackConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_attributes_counterproof_graph_exhaustively() {
        let operator_count = N_TEST_OPERATORS as u32;

        for graph_owner_idx in 0..operator_count {
            for pov_idx in 0..operator_count {
                // Counterproof slots are assigned to operators in ascending operator-index order,
                // with the graph owner's operator index omitted from the sequence entirely.
                // Zipping the dense slot range with the operator range minus the owner gives an
                // oracle derived directly from that protocol rule, without reproducing the slot
                // remapping arithmetic used by the implementation.
                for (counterproof_slot, expected_operator_idx) in (0..N_TEST_OPERATORS - 1)
                    .zip((0..operator_count).filter(|idx| *idx != graph_owner_idx))
                {
                    assert_counterproof_graph_attribution(
                        graph_owner_idx,
                        pov_idx,
                        counterproof_slot,
                        expected_operator_idx,
                    );
                }
            }
        }
    }

    #[test]
    fn classify_tx_recognizes_slash_in_all_nackd_and_acked() {
        let cfg = test_graph_sm_cfg();
        let slash_tx = TestGraphTxKind::Slash.into();

        let sm = create_sm(all_nackd_state());
        let result = sm.classify_tx(&cfg, &slash_tx, LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(GraphEvent::SlashConfirmed(_))),
            "expected Some(SlashConfirmed) in AllNackd but got {result:?}"
        );

        let sm = create_sm(acked_state());
        let result = sm.classify_tx(&cfg, &slash_tx, LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(GraphEvent::SlashConfirmed(_))),
            "expected Some(SlashConfirmed) in Acked but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_payout_connector_spent() {
        let cfg = test_graph_sm_cfg();
        let payout_connector_tx = test_payout_connector_spent_tx();
        for state in payout_connector_spent_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(&cfg, &payout_connector_tx, LATER_BLOCK_HEIGHT);
            assert!(
                matches!(result, Some(GraphEvent::PayoutConnectorSpent(_))),
                "expected Some(PayoutConnectorSpent) but got {result:?}"
            );
        }
    }

    // --- Negative tests: classify_tx returns None ---

    #[test]
    fn classify_tx_ignores_irrelevant_tx_in_all_states() {
        let cfg = test_graph_sm_cfg();
        let irrelevant_tx = generate_spending_tx(
            OutPoint {
                txid: generate_txid(),
                vout: 99,
            },
            &[],
        );

        for state in all_state_variants() {
            let sm = create_sm(state);
            let result = sm.classify_tx(&cfg, &irrelevant_tx, LATER_BLOCK_HEIGHT);
            assert!(result.is_none(), "expected None but got {:?}", result);
        }
    }

    #[test]
    fn classify_tx_returns_none_in_terminal_states() {
        let cfg = test_graph_sm_cfg();
        let claim_tx = TestGraphTxKind::Claim.into();
        let deposit_spend_tx = test_deposit_spend_tx();
        let payout_connector_tx = test_payout_connector_spent_tx();

        for state in terminal_states() {
            let sm = create_sm(state);

            let result = sm.classify_tx(&cfg, &claim_tx, LATER_BLOCK_HEIGHT);
            assert!(
                result.is_none(),
                "expected None for claim tx but got {:?}",
                result
            );
            let result = sm.classify_tx(&cfg, &deposit_spend_tx, LATER_BLOCK_HEIGHT);
            assert!(
                result.is_none(),
                "expected None for deposit spend tx but got {:?}",
                result
            );
            let result = sm.classify_tx(&cfg, &payout_connector_tx, LATER_BLOCK_HEIGHT);
            assert!(
                result.is_none(),
                "expected None for payout connector tx but got {:?}",
                result
            );
        }
    }

    #[test]
    fn classify_tx_returns_none_in_created() {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(GraphState::Created {
            last_block_height: LATER_BLOCK_HEIGHT,
        });

        let result = sm.classify_tx(&cfg, &TestGraphTxKind::Claim.into(), LATER_BLOCK_HEIGHT);
        assert!(
            result.is_none(),
            "expected None for claim tx but got {:?}",
            result
        );
        let result = sm.classify_tx(&cfg, &test_deposit_spend_tx(), LATER_BLOCK_HEIGHT);
        assert!(
            result.is_none(),
            "expected None for deposit spend tx but got {:?}",
            result
        );
        let result = sm.classify_tx(&cfg, &test_payout_connector_spent_tx(), LATER_BLOCK_HEIGHT);
        assert!(
            result.is_none(),
            "expected None for payout connector tx but got {:?}",
            result
        );
    }
}
