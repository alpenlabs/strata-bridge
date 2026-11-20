//! Unit Tests for process_payout_confirmed
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::{OutPoint, Transaction, Txid};

    use crate::deposit::{
        errors::DSMError,
        events::{DepositEvent, PayoutConfirmedEvent},
        state::DepositState,
        tests::*,
    };

    fn payout_confirmed_event(outpoint: OutPoint) -> DepositEvent {
        DepositEvent::PayoutConfirmed(PayoutConfirmedEvent {
            tx: test_payout_tx(outpoint),
        })
    }

    fn agreed_payout_states(
        fulfillment_txid: Txid,
        payout: CooperativePayoutTx,
    ) -> Vec<DepositState> {
        let deadline =
            INITIAL_BLOCK_HEIGHT + test_deposit_sm_cfg().cooperative_payout_timeout_blocks();
        let descriptor_received = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid,
            cooperative_payment_deadline: deadline,
            cooperative_payout_tx: payout.clone(),
            payout_nonces: BTreeMap::new(),
        };
        let data = descriptor_received.cooperative_payout_data();
        let payout_nonces: BTreeMap<_, _> = (0..N_TEST_OPERATORS)
            .map(|idx| (idx as u32, generate_pubnonce()))
            .collect();
        let payout_aggregated_nonce = AggNonce::sum(payout_nonces.values().cloned());
        let sweep_nonces: BTreeMap<_, _> = (0..N_TEST_OPERATORS)
            .map(|idx| (idx as u32, generate_pubnonce()))
            .collect();
        let sweep_agg_nonce = AggNonce::sum(sweep_nonces.values().cloned());
        vec![
            descriptor_received,
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                cooperative_payout_tx: payout.clone(),
                cooperative_payment_deadline: deadline,
                payout_nonces,
                payout_aggregated_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                last_block_height: deadline,
                expected_cooperative_payout_txid: Some(payout.as_ref().compute_txid()),
            },
            DepositState::SweepNoncesPending {
                last_block_height: deadline,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_nonces: BTreeMap::new(),
                cooperative_payout_data: data,
            },
            DepositState::SweepNoncesCollected {
                last_block_height: deadline,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_agg_nonce,
                sweep_nonces,
                sweep_partials: BTreeMap::new(),
                cooperative_payout_data: data,
            },
        ]
    }

    /// Tests correct transition from Deposited to Spent with unknown fulfillment txid.
    #[test]
    fn test_payout_confirmed_from_deposited_records_unknown_fulfillment_txid() {
        test_deposit_transition(DepositTransition {
            from_state: DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
                cooperative_payout_txid: None,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Tests correct transition from PayoutNoncesCollected to Spent with known fulfillment txid.
    #[test]
    fn test_payout_confirmed_from_payout_nonces_preserves_fulfillment_txid() {
        let desc = random_p2tr_desc();
        let fulfillment_txid = generate_txid();

        test_deposit_transition(DepositTransition {
            from_state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                cooperative_payout_tx: test_cooperative_payout_txn(desc),
                cooperative_payment_deadline: INITIAL_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
                payout_nonces: test_operator_nonces(),
                payout_aggregated_nonce: AggNonce::sum(test_operator_nonces().values().cloned()),
                payout_partial_signatures: BTreeMap::new(),
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: None,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Tests correct transition from Assigned to Spent: the assignee is preserved but no
    /// fulfillment has happened, so the fulfillment txid is unknown.
    #[test]
    fn test_payout_confirmed_from_assigned_preserves_assignee_only() {
        test_deposit_transition(DepositTransition {
            from_state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: random_p2tr_desc(),
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: None,
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: None,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Tests correct transition from Fulfilled to Spent preserving assignee and fulfillment txid.
    #[test]
    fn test_payout_confirmed_from_fulfilled_preserves_fulfillment_txid() {
        let fulfillment_txid = generate_txid();

        test_deposit_transition(DepositTransition {
            from_state: DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: INITIAL_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: None,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Tests correct transition from PayoutDescriptorReceived to Spent preserving assignee and
    /// fulfillment txid.
    #[test]
    fn test_payout_confirmed_from_payout_descriptor_received_preserves_fulfillment_txid() {
        let fulfillment_txid = generate_txid();

        test_deposit_transition(DepositTransition {
            from_state: DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                cooperative_payment_deadline: INITIAL_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
                cooperative_payout_tx: test_cooperative_payout_txn(random_p2tr_desc()),
                payout_nonces: BTreeMap::new(),
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: None,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Tests correct transition from CooperativePathFailed to Spent with known fulfillment txid.
    #[test]
    fn test_payout_confirmed_from_cooperative_path_failed_preserves_fulfillment_txid() {
        let fulfillment_txid = generate_txid();

        test_deposit_transition(DepositTransition {
            from_state: DepositState::CooperativePathFailed {
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                last_block_height: INITIAL_BLOCK_HEIGHT,
                expected_cooperative_payout_txid: None,
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: None,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// Tests correct transition from the sweep states to Spent with unknown fulfillment txid:
    /// either the sweep itself or a racing payout spent the deposit outpoint.
    #[test]
    fn test_payout_confirmed_from_sweep_states_records_unknown_fulfillment_txid() {
        let sweep_states = [
            DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_nonces: BTreeMap::new(),
                cooperative_payout_data: None,
            },
            DepositState::SweepNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_agg_nonce: AggNonce::sum(test_operator_nonces().values().cloned()),
                sweep_nonces: test_operator_nonces(),
                sweep_partials: BTreeMap::new(),
                cooperative_payout_data: None,
            },
        ];

        for state in sweep_states {
            test_deposit_transition(DepositTransition {
                from_state: state,
                event: payout_confirmed_event(test_deposit_outpoint()),
                expected_state: DepositState::Spent {
                    fulfillment_txid: None,
                    assignee: None,
                    cooperative_payout_txid: None,
                },
                expected_duties: vec![],
                expected_signals: vec![],
            });
        }
    }

    /// Tests that PayoutConfirmed is rejected if the payout tx does not spend the deposit outpoint.
    #[test]
    fn test_payout_confirmed_rejected_for_wrong_outpoint_from_valid_states() {
        let desc = random_p2tr_desc();
        let fulfillment_txid = generate_txid();
        let wrong_outpoint = OutPoint {
            txid: generate_txid(),
            vout: 99,
        };

        let valid_states = [
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: random_p2tr_desc(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: INITIAL_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                cooperative_payment_deadline: INITIAL_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
                cooperative_payout_tx: test_cooperative_payout_txn(desc.clone()),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                cooperative_payout_tx: test_cooperative_payout_txn(desc),
                cooperative_payment_deadline: INITIAL_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
                payout_nonces: test_operator_nonces(),
                payout_aggregated_nonce: AggNonce::sum(test_operator_nonces().values().cloned()),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                last_block_height: INITIAL_BLOCK_HEIGHT,
                expected_cooperative_payout_txid: None,
            },
            DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_nonces: BTreeMap::new(),
                cooperative_payout_data: None,
            },
            DepositState::SweepNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_agg_nonce: AggNonce::sum(test_operator_nonces().values().cloned()),
                sweep_nonces: test_operator_nonces(),
                sweep_partials: BTreeMap::new(),
                cooperative_payout_data: None,
            },
        ];

        for state in valid_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: payout_confirmed_event(wrong_outpoint),
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            });
        }
    }

    /// Tests duplicate detection in terminal Spent states.
    #[test]
    fn test_payout_confirmed_duplicate_in_spent() {
        let spent_states = [
            DepositState::Spent {
                fulfillment_txid: Some(generate_txid()),
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: None,
            },
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
                cooperative_payout_txid: None,
            },
        ];

        for state in spent_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: payout_confirmed_event(test_deposit_outpoint()),
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            });
        }
    }

    /// Tests that the pre-deposit states and Aborted (the states with no live deposit UTXO)
    /// should NOT accept the PayoutConfirmed event.
    #[test]
    fn test_payout_confirmed_invalid_from_other_states() {
        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                claim_txids: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Aborted,
            DepositState::Skipped,
        ];

        for state in invalid_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: payout_confirmed_event(test_deposit_outpoint()),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }

    #[test]
    fn test_matching_cooperative_payout_retains_txid_and_withdrawal() {
        let fulfillment_txid = generate_txid();
        let payout = test_cooperative_payout_txn(random_p2tr_desc());
        let tx = payout.as_ref().clone();
        for state in agreed_payout_states(fulfillment_txid, payout) {
            let encoded = postcard::to_allocvec(&state).unwrap();
            let state: DepositState = postcard::from_bytes(&encoded).unwrap();
            test_deposit_transition(DepositTransition {
                from_state: state,
                event: DepositEvent::PayoutConfirmed(PayoutConfirmedEvent { tx: tx.clone() }),
                expected_state: DepositState::Spent {
                    fulfillment_txid: Some(fulfillment_txid),
                    assignee: Some(TEST_ASSIGNEE),
                    cooperative_payout_txid: Some(tx.compute_txid()),
                },
                expected_duties: vec![],
                expected_signals: vec![],
            });
        }
    }

    #[test]
    fn test_other_spends_do_not_report_cooperative_payout() {
        let payout = test_cooperative_payout_txn(random_p2tr_desc());
        let other_transactions: [Transaction; 3] = [
            test_sweep_txn(random_p2tr_desc()).as_ref().clone(),
            test_cooperative_payout_txn(random_p2tr_desc())
                .as_ref()
                .clone(),
            test_payout_tx(test_deposit_outpoint()),
        ];
        let fulfillment_txid = generate_txid();
        for tx in other_transactions {
            for state in agreed_payout_states(fulfillment_txid, payout.clone()) {
                let is_sweeping = matches!(
                    state,
                    DepositState::SweepNoncesPending { .. }
                        | DepositState::SweepNoncesCollected { .. }
                );
                test_deposit_transition(DepositTransition {
                    from_state: state,
                    event: DepositEvent::PayoutConfirmed(PayoutConfirmedEvent { tx: tx.clone() }),
                    expected_state: DepositState::Spent {
                        fulfillment_txid: (!is_sweeping).then_some(fulfillment_txid),
                        assignee: (!is_sweeping).then_some(TEST_ASSIGNEE),
                        cooperative_payout_txid: None,
                    },
                    expected_duties: vec![],
                    expected_signals: vec![],
                });
            }
        }
    }

    #[test]
    fn test_late_cooperative_payout_survives_timeout_and_roundtrip() {
        let deadline =
            INITIAL_BLOCK_HEIGHT + test_deposit_sm_cfg().cooperative_payout_timeout_blocks();
        let fulfillment_txid = generate_txid();
        let payout = test_cooperative_payout_txn(random_p2tr_desc());
        let tx = payout.as_ref().clone();
        // Both signing phases retain the expected TXID when the cooperative deadline expires.
        for state in agreed_payout_states(fulfillment_txid, payout)
            .into_iter()
            .take(2)
        {
            let mut sm = create_sm(state);
            sm.process_new_block(NewBlockEvent {
                block_height: deadline,
            })
            .unwrap();
            assert_eq!(
                sm.state(),
                &DepositState::CooperativePathFailed {
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid,
                    last_block_height: deadline,
                    expected_cooperative_payout_txid: Some(tx.compute_txid()),
                }
            );
            let encoded = postcard::to_allocvec(&sm).unwrap();
            let mut recovered: DepositSM = postcard::from_bytes(&encoded).unwrap();
            recovered
                .process_payout_confirmed(&PayoutConfirmedEvent { tx: tx.clone() })
                .unwrap();
            let expected = DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: Some(tx.compute_txid()),
            };
            assert_eq!(recovered.state(), &expected);
            let encoded = postcard::to_allocvec(&recovered).unwrap();
            let mut recovered: DepositSM = postcard::from_bytes(&encoded).unwrap();
            assert_eq!(recovered.state(), &expected);
            assert!(matches!(
                recovered.process_payout_confirmed(&PayoutConfirmedEvent { tx: tx.clone() }),
                Err(DSMError::Duplicate { .. })
            ));
            assert_eq!(recovered.state(), &expected);
        }
    }

    #[test]
    fn test_payout_without_agreement_is_unclassified() {
        let payout = test_cooperative_payout_txn(random_p2tr_desc());
        let fulfillment_txid = generate_txid();
        test_deposit_transition(DepositTransition {
            from_state: DepositState::CooperativePathFailed {
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                last_block_height: INITIAL_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
                expected_cooperative_payout_txid: None,
            },
            event: DepositEvent::PayoutConfirmed(PayoutConfirmedEvent {
                tx: payout.as_ref().clone(),
            }),
            expected_state: DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
                cooperative_payout_txid: None,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }
}
