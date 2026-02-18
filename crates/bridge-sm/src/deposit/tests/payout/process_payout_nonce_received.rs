//! Unit Tests for process_payout_nonce_received
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::{Txid, hashes::Hash};
    use musig2::{AggNonce, PubNonce};

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, PayoutNonceReceivedEvent},
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    /// tests partial collection: first nonce received, stays in PayoutDescriptorReceived state
    #[test]
    fn test_payout_nonce_received_partial_collection() {
        let desc = random_p2tr_desc();

        let nonce = generate_pubnonce();

        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        let state = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            cooperative_payout_tx: cooperative_payout_tx.clone(),
            payout_nonces: BTreeMap::new(),
        };

        let mut expected_nonces = BTreeMap::new();
        expected_nonces.insert(TEST_ARBITRARY_OPERATOR_IDX, nonce.clone());

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
                payout_nonce: nonce,
                operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
            }),
            expected_state: DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx,
                payout_nonces: expected_nonces,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests partial collection: nonce received with existing nonces (not yet complete),
    /// stays in PayoutDescriptorReceived state
    #[test]
    fn test_payout_nonce_received_second_nonce() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        // Generate nonces for all operators except the last one.
        // This ensures collection can never complete in this test.
        let nonces: BTreeMap<OperatorIdx, PubNonce> = (0..N_TEST_OPERATORS - 1)
            .map(|idx| (idx as OperatorIdx, generate_pubnonce()))
            .collect();

        // Split into initial (all but last generated) and incoming (last generated)
        let (&incoming_idx, _) = nonces.iter().last().unwrap();
        let initial_nonces: BTreeMap<_, _> = nonces
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let incoming_nonce = nonces[&incoming_idx].clone();

        let state = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            cooperative_payout_tx: cooperative_payout_tx.clone(),
            payout_nonces: initial_nonces,
        };

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
                payout_nonce: incoming_nonce,
                operator_idx: incoming_idx,
            }),
            expected_state: DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx,
                payout_nonces: nonces,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests all nonces collected with POV operator NOT being the assignee - should emit
    /// PublishPayoutPartial duty
    #[test]
    fn test_payout_nonce_received_all_collected_pov_is_not_assignee() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        // Generate nonces for all operators
        let all_nonces: BTreeMap<OperatorIdx, PubNonce> = (0..N_TEST_OPERATORS)
            .map(|idx| (idx as OperatorIdx, generate_pubnonce()))
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_nonces.iter().last().unwrap();
        let initial_nonces: BTreeMap<_, _> = all_nonces
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let incoming_nonce = all_nonces[&incoming_idx].clone();

        let state = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_NONPOV_IDX,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            cooperative_payout_tx: cooperative_payout_tx.clone(),
            payout_nonces: initial_nonces,
        };

        // Compute expected aggregated nonce
        let expected_agg_nonce = AggNonce::sum(all_nonces.values().cloned());

        // Get the payout sighash from the cooperative payout tx
        let payout_sighash = cooperative_payout_tx
            .signing_info()
            .first()
            .expect("cooperative payout transaction must have signing info")
            .sighash;

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
                payout_nonce: incoming_nonce,
                operator_idx: incoming_idx,
            }),
            expected_state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: all_nonces,
                payout_aggregated_nonce: expected_agg_nonce.clone(),
                payout_partial_signatures: BTreeMap::new(),
            },
            expected_duties: vec![DepositDuty::PublishPayoutPartial {
                deposit_idx: TEST_DEPOSIT_IDX,
                deposit_outpoint: test_deposit_outpoint(),
                payout_sighash,
                agg_nonce: expected_agg_nonce,
                ordered_pubkeys: test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX)
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect(),
            }],
            expected_signals: vec![],
        });
    }

    /// tests all nonces collected with POV operator being the assignee - should NOT emit any duty
    #[test]
    fn test_payout_nonce_received_all_collected_pov_is_assignee() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        // Generate nonces for all operators
        let all_nonces: BTreeMap<OperatorIdx, PubNonce> = (0..N_TEST_OPERATORS)
            .map(|idx| (idx as OperatorIdx, generate_pubnonce()))
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_nonces.iter().last().unwrap();
        let initial_nonces: BTreeMap<_, _> = all_nonces
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, v)| (k, v.clone()))
            .collect();
        let incoming_nonce = all_nonces[&incoming_idx].clone();

        let state = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_POV_IDX,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            cooperative_payout_tx: cooperative_payout_tx.clone(),
            payout_nonces: initial_nonces,
        };

        // Compute expected aggregated nonce
        let expected_agg_nonce = AggNonce::sum(all_nonces.values().cloned());

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
                payout_nonce: incoming_nonce,
                operator_idx: incoming_idx,
            }),
            expected_state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: all_nonces,
                payout_aggregated_nonce: expected_agg_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            expected_duties: vec![], // No duty since POV is the assignee
            expected_signals: vec![],
        });
    }

    /// tests duplicate detection: same operator sends same nonce twice
    #[test]
    fn test_payout_nonce_received_duplicate_same_nonce() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        let nonce = generate_pubnonce();

        let initial_state = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            cooperative_payout_tx,
            payout_nonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut sequence = EventSequence::new(sm, get_state);

        let nonce_event = DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
            payout_nonce: nonce,
            operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
        });

        sequence.process(test_deposit_sm_cfg(), nonce_event.clone());
        sequence.assert_no_errors();
        // Second submission with same nonce - should fail with Duplicate
        sequence.process(test_deposit_sm_cfg(), nonce_event);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            1,
            "Expected 1 error (duplicate), got {}",
            errors.len()
        );
        assert!(
            matches!(errors[0], DSMError::Duplicate { .. }),
            "Expected Duplicate error, got {:?}",
            errors[0]
        );
    }

    /// tests duplicate detection: same operator sends different nonce (still duplicate by operator)
    #[test]
    fn test_payout_nonce_received_duplicate_different_nonce() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        let first_nonce = generate_pubnonce();
        let duplicate_nonce = generate_pubnonce();

        let initial_state = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            cooperative_payout_tx,
            payout_nonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut sequence = EventSequence::new(sm, get_state);

        let first_event = DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
            payout_nonce: first_nonce,
            operator_idx: TEST_POV_IDX,
        });
        let duplicate_event = DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
            payout_nonce: duplicate_nonce,
            operator_idx: TEST_POV_IDX,
        });

        sequence.process(test_deposit_sm_cfg(), first_event);
        sequence.assert_no_errors();
        // Second submission with different nonce but same operator - should fail with Duplicate
        sequence.process(test_deposit_sm_cfg(), duplicate_event);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            1,
            "Expected 1 error (duplicate), got {}",
            errors.len()
        );
        assert!(
            matches!(errors[0], DSMError::Duplicate { .. }),
            "Expected Duplicate error, got {:?}",
            errors[0]
        );
    }

    /// tests that invalid operator index is rejected
    #[test]
    fn test_invalid_operator_idx_in_payout_nonce_received() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        let initial_state = DepositState::PayoutDescriptorReceived {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            cooperative_payout_tx,
            payout_nonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process PayoutNonceReceived with invalid operator idx
        let nonce = generate_pubnonce();
        let event = DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
            payout_nonce: nonce,
            operator_idx: u32::MAX,
        });
        seq.process(test_deposit_sm_cfg(), event.clone());

        // Verify rejection with test_invalid_transition
        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: seq.state().clone(),
            event,
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }

    /// tests that all states except PayoutDescriptorReceived should reject PayoutNonceReceived
    /// event
    #[test]
    fn test_payout_nonce_received_invalid_from_other_states() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(desc.clone());

        let nonce = generate_pubnonce();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Spent,
            DepositState::Aborted,
        ];

        for state in invalid_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: DepositEvent::PayoutNonceReceived(PayoutNonceReceivedEvent {
                    payout_nonce: nonce.clone(),
                    operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
                }),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }
}
