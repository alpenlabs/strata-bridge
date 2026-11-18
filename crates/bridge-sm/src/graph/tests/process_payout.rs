//! Unit Tests for process_payout transitions.
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;
    use zkaleido::ProofReceipt;

    use crate::graph::{
        errors::GSMError,
        events::{GraphEvent, PayoutConfirmedEvent},
        state::{CounterproofData, GraphState, PayoutKind},
        tests::{
            ASSIGNMENT_DEADLINE, CLAIM_BLOCK_HEIGHT, GraphInvalidTransition, GraphTransition,
            INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT, TEST_NONPOV_IDX, TEST_POV_IDX, create_sm,
            dummy_proof_receipt,
            mock_states::{
                all_nackd_state, assigned_state, bridge_proof_posted_state, claimed_state,
                contested_state, counter_proof_posted_state,
            },
            test_bridge_proof_tx, test_completed_signatures, test_deposit_params,
            test_graph_invalid_transition, test_graph_summary, test_graph_transition,
            test_recipient_desc,
        },
    };

    fn counter_proof_posted_state_with_proof(proof: Option<ProofReceipt>) -> GraphState {
        let mut state = counter_proof_posted_state();
        let GraphState::CounterProofPosted {
            last_block_height,
            refuted_bridge_proof,
            counterproofs_and_confs,
            ..
        } = &mut state
        else {
            unreachable!();
        };
        *last_block_height = LATER_BLOCK_HEIGHT + 1;
        *refuted_bridge_proof = proof.map(|receipt| (test_bridge_proof_tx(), receipt));
        counterproofs_and_confs.insert(
            TEST_NONPOV_IDX,
            CounterproofData {
                txid: test_graph_summary().counterproofs[0].counterproof,
                conf_height: LATER_BLOCK_HEIGHT + 1,
                completed_signatures: test_completed_signatures(),
            },
        );
        state
    }

    #[test]
    fn test_payout_from_claimed() {
        let graph_summary = test_graph_summary();
        let claim_txid = graph_summary.claim;
        let payout_txid = graph_summary.uncontested_payout;

        test_graph_transition(GraphTransition {
            from_state: GraphState::Claimed {
                last_block_height: CLAIM_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary,
                signatures: Default::default(),
                fulfillment_txid: Some(generate_txid()),
                fulfillment_block_height: Some(INITIAL_BLOCK_HEIGHT),
                claim_block_height: CLAIM_BLOCK_HEIGHT,
                stake_spent: None,
                payout_connector_spent: None,
            },
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent { payout_txid }),
            expected_state: GraphState::Withdrawn {
                claim_txid,
                payout_txid,
                payout_kind: Some(PayoutKind::Uncontested),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_payout_rejected_invalid_txid() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: claimed_state(CLAIM_BLOCK_HEIGHT, generate_txid(), Default::default()),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_payout_from_all_nackd() {
        let graph_summary = test_graph_summary();
        let claim_txid = graph_summary.claim;
        let payout_txid = graph_summary.contested_payout;

        test_graph_transition(GraphTransition {
            from_state: all_nackd_state(),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent { payout_txid }),
            expected_state: GraphState::Withdrawn {
                claim_txid,
                payout_txid,
                payout_kind: Some(PayoutKind::Contested),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_payout_from_all_nackd_rejected_invalid_txid() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: all_nackd_state(),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_duplicate_payout_preserves_kind() {
        let graph_summary = test_graph_summary();
        for (payout_kind, payout_txid) in [
            // Completed payout with no retained payout kind.
            (None, graph_summary.uncontested_payout),
            (
                Some(PayoutKind::Uncontested),
                graph_summary.uncontested_payout,
            ),
            (Some(PayoutKind::Contested), graph_summary.contested_payout),
        ] {
            let state = GraphState::Withdrawn {
                claim_txid: graph_summary.claim,
                payout_txid,
                payout_kind,
            };
            let mut sm = create_sm(state.clone());
            let err = sm
                .process_payout(PayoutConfirmedEvent { payout_txid })
                .unwrap_err();
            assert!(
                matches!(err, GSMError::Duplicate { .. }),
                "unexpected error: {err:?}"
            );
            assert_eq!(
                sm.state, state,
                "duplicate payout must not alter the retained kind"
            );
        }
    }

    #[test]
    fn test_payout_from_bridge_proof_posted() {
        let graph_summary = test_graph_summary();
        let claim_txid = graph_summary.claim;
        let payout_txid = graph_summary.contested_payout;

        test_graph_transition(GraphTransition {
            from_state: GraphState::BridgeProofPosted {
                last_block_height: LATER_BLOCK_HEIGHT + 1,
                graph_data: test_deposit_params(),
                graph_summary,
                signatures: Default::default(),
                fulfillment_txid: Some(generate_txid()),
                contest_block_height: LATER_BLOCK_HEIGHT,
                bridge_proof_tx: test_bridge_proof_tx(),
                bridge_proof_block_height: LATER_BLOCK_HEIGHT + 1,
                proof: dummy_proof_receipt(),
                stake_spent: None,
                payout_connector_spent: None,
            },
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent { payout_txid }),
            expected_state: GraphState::Withdrawn {
                claim_txid,
                payout_txid,
                payout_kind: Some(PayoutKind::Contested),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_payout_from_bridge_proof_posted_rejected_invalid_txid() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: bridge_proof_posted_state(),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_payout_from_contested() {
        let graph_summary = test_graph_summary();
        let claim_txid = graph_summary.claim;
        let payout_txid = graph_summary.contested_payout;

        test_graph_transition(GraphTransition {
            from_state: contested_state(),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent { payout_txid }),
            expected_state: GraphState::Withdrawn {
                claim_txid,
                payout_txid,
                payout_kind: Some(PayoutKind::Contested),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_payout_from_contested_rejected_invalid_txid() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: contested_state(),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_payout_from_counter_proof_posted() {
        let graph_summary = test_graph_summary();
        let claim_txid = graph_summary.claim;
        let payout_txid = graph_summary.contested_payout;

        for refuted_proof in [None, Some(dummy_proof_receipt())] {
            let from_state = counter_proof_posted_state_with_proof(refuted_proof);
            test_graph_transition(GraphTransition {
                from_state,
                event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent { payout_txid }),
                expected_state: GraphState::Withdrawn {
                    claim_txid,
                    payout_txid,
                    payout_kind: Some(PayoutKind::Contested),
                },
                expected_duties: vec![],
                expected_signals: vec![],
            });
        }
    }

    #[test]
    fn test_payout_from_counter_proof_posted_rejected_invalid_txid() {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: counter_proof_posted_state(),
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_payout_from_invalid_state() {
        let state = assigned_state(TEST_POV_IDX, ASSIGNMENT_DEADLINE, test_recipient_desc(1));

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                payout_txid: generate_txid(),
            }),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
