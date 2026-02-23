//! Unit tests for the [`TxClassifier`] implementation on [`GraphSM`].
//!
//! These are exhaustive unit tests (not proptests) because classify_tx's
//! behavior depends on the state *variant*, not the field values within each
//! variant. Enumerating every variant gives guaranteed exhaustive coverage.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_txid};

    use crate::{graph::tests::*, tx_classifier::TxClassifier};

    // --- State constructors ---

    /// States that can detect a malicious claim (pre-signing states with a graph_summary).
    fn pre_signing_states() -> Vec<GraphState> {
        let summary = test_graph_summary();
        let params = test_deposit_params();

        vec![
            GraphState::GraphGenerated {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: params,
                graph_summary: summary.clone(),
            },
            GraphState::AdaptorsVerified {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: params,
                graph_summary: summary.clone(),
                pubnonces: Default::default(),
            },
            GraphState::NoncesCollected {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: params,
                graph_summary: summary.clone(),
                pubnonces: Default::default(),
                agg_nonces: Default::default(),
                partial_signatures: Default::default(),
            },
            GraphState::GraphSigned {
                last_block_height: LATER_BLOCK_HEIGHT,
                graph_data: params,
                graph_summary: summary,
                signatures: Default::default(),
            },
        ]
    }

    fn assigned_state() -> GraphState {
        GraphState::Assigned {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            assignee: TEST_ASSIGNEE,
            deadline: LATER_BLOCK_HEIGHT + 15,
            recipient_desc: test_recipient_desc(1),
        }
    }

    fn fulfilled_state() -> GraphState {
        GraphState::Fulfilled {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: LATER_BLOCK_HEIGHT,
        }
    }

    fn claimed_state() -> GraphState {
        GraphState::Claimed {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            fulfillment_txid: Some(generate_txid()),
            fulfillment_block_height: Some(LATER_BLOCK_HEIGHT),
            claim_block_height: LATER_BLOCK_HEIGHT,
        }
    }

    fn contested_state() -> GraphState {
        GraphState::Contested {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            fulfillment_txid: Some(generate_txid()),
            fulfillment_block_height: Some(LATER_BLOCK_HEIGHT),
            contest_block_height: LATER_BLOCK_HEIGHT,
        }
    }

    fn bridge_proof_posted_state() -> GraphState {
        GraphState::BridgeProofPosted {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            contest_block_height: LATER_BLOCK_HEIGHT,
            bridge_proof_txid: generate_txid(),
            bridge_proof_block_height: LATER_BLOCK_HEIGHT,
            proof: dummy_proof_receipt(),
        }
    }

    fn bridge_proof_timedout_state() -> GraphState {
        GraphState::BridgeProofTimedout {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_slash_txid: generate_txid(),
            claim_txid: generate_txid(),
        }
    }

    fn counter_proof_posted_state() -> GraphState {
        GraphState::CounterProofPosted {
            last_block_height: LATER_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            contest_block_height: LATER_BLOCK_HEIGHT,
            counterproofs_and_confs: BTreeMap::new(),
            counterproof_nacks: BTreeMap::new(),
        }
    }

    fn all_nackd_state() -> GraphState {
        GraphState::AllNackd {
            last_block_height: LATER_BLOCK_HEIGHT,
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_payout_txid: Transaction::from(TestGraphTxKind::ContestedPayout)
                .compute_txid(),
            possible_slash_txid: Transaction::from(TestGraphTxKind::Slash).compute_txid(),
        }
    }

    fn acked_state() -> GraphState {
        GraphState::Acked {
            last_block_height: LATER_BLOCK_HEIGHT,
            contest_block_height: LATER_BLOCK_HEIGHT,
            expected_slash_txid: Transaction::from(TestGraphTxKind::Slash).compute_txid(),
            claim_txid: generate_txid(),
        }
    }

    /// States that may observe a claim tx.
    fn claim_detecting_states() -> Vec<GraphState> {
        let mut states = pre_signing_states();
        states.push(assigned_state());
        states.push(fulfilled_state());
        states
    }

    /// States that expect payout via deposit spend.
    fn uncontested_payout_detecting_states() -> Vec<GraphState> {
        vec![claimed_state()]
    }

    /// States that expect payout via deposit spend.
    fn contested_payout_detecting_states() -> Vec<GraphState> {
        vec![bridge_proof_posted_state(), all_nackd_state()]
    }

    /// States that detect counterproof txids.
    fn counterproof_detecting_states() -> Vec<GraphState> {
        vec![contested_state(), bridge_proof_posted_state()]
    }

    /// States that detect a payout connector spend (via admin or unstaking burn txs).
    ///
    /// These states use `graph_summary.claim` or `claim_txid` to identify the payout
    /// connector outpoint.
    fn payout_connector_spent_states() -> Vec<GraphState> {
        vec![
            claimed_state(),
            contested_state(),
            bridge_proof_posted_state(),
            bridge_proof_timedout_state(),
            counter_proof_posted_state(),
        ]
    }

    fn terminal_states() -> Vec<GraphState> {
        vec![
            GraphState::Withdrawn {
                payout_txid: generate_txid(),
            },
            GraphState::Slashed {
                slash_txid: generate_txid(),
            },
            GraphState::Aborted {
                payout_connector_spend_txid: generate_txid(),
                reason: "test".to_string(),
            },
        ]
    }

    /// One representative of every state variant.
    fn all_state_variants() -> Vec<GraphState> {
        let mut states = vec![GraphState::Created {
            last_block_height: LATER_BLOCK_HEIGHT,
        }];
        states.extend(pre_signing_states());
        states.push(assigned_state());
        states.push(fulfilled_state());
        states.push(claimed_state());
        states.push(contested_state());
        states.push(bridge_proof_posted_state());
        states.push(bridge_proof_timedout_state());
        states.push(counter_proof_posted_state());
        states.push(all_nackd_state());
        states.push(acked_state());
        states.extend(terminal_states());
        states
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
        let sm = create_sm(assigned_state());
        let result = sm.classify_tx(&cfg, &test_fulfillment_tx(), LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(GraphEvent::FulfillmentConfirmed(_))),
            "expected Some(FulfillmentConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_contest_in_claimed() {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(claimed_state());
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
