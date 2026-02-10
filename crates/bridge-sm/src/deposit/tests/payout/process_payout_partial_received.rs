//! Unit Tests for process_payout_partial_received
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::{Txid, hashes::Hash};
    use musig2::{AggNonce, PubNonce};

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, PayoutPartialReceivedEvent},
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    /// Helper to create test setup for payout partial tests.
    /// Returns (state, signers, key_agg_ctx, agg_nonce, message, cooperative_payout_tx,
    /// expected_payout_tx).
    fn create_payout_partial_test_setup(
        assignee: OperatorIdx,
    ) -> (
        DepositState,
        Vec<TestMusigSigner>,
        musig2::KeyAggContext,
        AggNonce,
        Message,
        strata_bridge_tx_graph2::transactions::prelude::CooperativePayoutTx,
        Transaction, // expected payout_tx for PublishPayout duty
    ) {
        let signers = test_operator_signers();
        let operator_desc = random_p2tr_desc();

        // Build cooperative payout tx and get signing info
        let payout_tx = test_payout_txn(operator_desc.clone());
        let (key_agg_ctx, message) = get_payout_signing_info(&payout_tx, &signers);
        let expected_payout_tx = payout_tx.as_ref().clone();

        // Generate nonces (counter=0 for this signing round)
        let agg_pubkey = key_agg_ctx.aggregated_pubkey();
        let nonce_counter = 0u64;
        let nonces: BTreeMap<OperatorIdx, PubNonce> = signers
            .iter()
            .map(|s| (s.operator_idx(), s.pubnonce(agg_pubkey, nonce_counter)))
            .collect();
        let agg_nonce = AggNonce::sum(nonces.values().cloned());

        let state = DepositState::PayoutNoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee,
            cooperative_payout_tx: payout_tx.clone(),
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            payout_nonces: nonces,
            payout_aggregated_nonce: agg_nonce.clone(),
            payout_partial_signatures: BTreeMap::new(),
        };

        (
            state,
            signers,
            key_agg_ctx,
            agg_nonce,
            message,
            payout_tx,
            expected_payout_tx,
        )
    }

    /// tests partial collection: first partial received, stays in PayoutNoncesCollected state
    #[test]
    fn test_payout_partial_received_partial_collection() {
        let (state, signers, key_agg_ctx, agg_nonce, message, cooperative_payout_tx, _) =
            create_payout_partial_test_setup(TEST_ASSIGNEE);

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::PayoutNoncesCollected { payout_nonces, .. } = &state {
            payout_nonces.clone()
        } else {
            panic!("Expected PayoutNoncesCollected state");
        };

        // Generate valid partial signature from a non-assignee operator
        let nonce_counter = 0u64;
        let partial_sig = signers[TEST_NON_ASSIGNEE_IDX as usize].sign(
            &key_agg_ctx,
            nonce_counter,
            &agg_nonce,
            message,
        );

        let mut expected_partials = BTreeMap::new();
        expected_partials.insert(TEST_NON_ASSIGNEE_IDX, partial_sig);

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
                partial_signature: partial_sig,
                operator_idx: TEST_NON_ASSIGNEE_IDX,
            }),
            expected_state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: nonces,
                payout_aggregated_nonce: agg_nonce,
                payout_partial_signatures: expected_partials,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests all partials collected when POV is the assignee - should emit
    /// PublishPayout duty
    #[test]
    fn test_payout_partial_received_all_collected_pov_is_assignee() {
        let (
            mut state,
            signers,
            key_agg_ctx,
            agg_nonce,
            message,
            cooperative_payout_tx,
            expected_payout_tx,
        ) = create_payout_partial_test_setup(TEST_POV_IDX);

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::PayoutNoncesCollected { payout_nonces, .. } = &state {
            payout_nonces.clone()
        } else {
            panic!("Expected PayoutNoncesCollected state");
        };

        // Generate partial signatures for all non-assignee operators
        let nonce_counter = 0u64;
        let all_partials: BTreeMap<OperatorIdx, _> = signers
            .iter()
            .filter(|s| s.operator_idx() != TEST_POV_IDX)
            .map(|s| {
                let sig = s.sign(&key_agg_ctx, nonce_counter, &agg_nonce, message);
                (s.operator_idx(), sig)
            })
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_partials.iter().last().unwrap();
        let initial_partials: BTreeMap<_, _> = all_partials
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, &v)| (k, v))
            .collect();
        let incoming_partial = all_partials[&incoming_idx];

        // Pre-populate state with initial partials
        if let DepositState::PayoutNoncesCollected {
            payout_partial_signatures,
            ..
        } = &mut state
        {
            *payout_partial_signatures = initial_partials;
        }

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
                partial_signature: incoming_partial,
                operator_idx: incoming_idx,
            }),
            expected_state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: nonces,
                payout_aggregated_nonce: agg_nonce,
                payout_partial_signatures: all_partials,
            },
            expected_duties: vec![DepositDuty::PublishPayout {
                payout_tx: expected_payout_tx,
            }],
            expected_signals: vec![],
        });
    }

    /// tests all partials collected when POV is NOT the assignee - should NOT
    /// emit any duty
    #[test]
    fn test_payout_partial_received_all_collected_pov_is_not_assignee() {
        let (mut state, signers, key_agg_ctx, agg_nonce, message, cooperative_payout_tx, _) =
            create_payout_partial_test_setup(TEST_NONPOV_IDX);

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::PayoutNoncesCollected { payout_nonces, .. } = &state {
            payout_nonces.clone()
        } else {
            panic!("Expected PayoutNoncesCollected state");
        };

        // Generate partial signatures for all non-assignee operators
        let nonce_counter = 0u64;
        let all_partials: BTreeMap<OperatorIdx, _> = signers
            .iter()
            .filter(|s| s.operator_idx() != TEST_NONPOV_IDX)
            .map(|s| {
                let sig = s.sign(&key_agg_ctx, nonce_counter, &agg_nonce, message);
                (s.operator_idx(), sig)
            })
            .collect();

        // Split into initial (all but last) and incoming (last)
        let (&incoming_idx, _) = all_partials.iter().last().unwrap();
        let initial_partials: BTreeMap<_, _> = all_partials
            .iter()
            .filter(|&(&k, _)| k != incoming_idx)
            .map(|(&k, &v)| (k, v))
            .collect();
        let incoming_partial = all_partials[&incoming_idx];

        // Pre-populate state with initial partials
        if let DepositState::PayoutNoncesCollected {
            payout_partial_signatures,
            ..
        } = &mut state
        {
            *payout_partial_signatures = initial_partials;
        }

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
                partial_signature: incoming_partial,
                operator_idx: incoming_idx,
            }),
            expected_state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: nonces,
                payout_aggregated_nonce: agg_nonce,
                payout_partial_signatures: all_partials,
            },
            expected_duties: vec![], // No duty since POV is not assignee
            expected_signals: vec![],
        });
    }

    /// tests duplicate detection: same operator sends same partial signature twice
    #[test]
    fn test_payout_partial_received_duplicate_same_signature() {
        let (state, signers, key_agg_ctx, agg_nonce, message, _, _) =
            create_payout_partial_test_setup(TEST_ASSIGNEE);

        let sm = create_sm(state);
        let mut sequence = EventSequence::new(sm, get_state);

        // Generate valid partial signature from a non-assignee operator
        let nonce_counter = 0u64;
        let partial_sig = signers[TEST_NON_ASSIGNEE_IDX as usize].sign(
            &key_agg_ctx,
            nonce_counter,
            &agg_nonce,
            message,
        );

        let event = DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
            partial_signature: partial_sig,
            operator_idx: TEST_NON_ASSIGNEE_IDX,
        });

        sequence.process(test_deposit_sm_cfg(), event.clone());
        sequence.assert_no_errors();
        // Second submission with same signature - should fail with Duplicate
        sequence.process(test_deposit_sm_cfg(), event);

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

    /// tests duplicate detection: same operator sends different partial signature
    #[test]
    fn test_payout_partial_received_duplicate_different_signature() {
        let (state, signers, key_agg_ctx, agg_nonce, message, _, _) =
            create_payout_partial_test_setup(TEST_ASSIGNEE);

        let sm = create_sm(state);
        let mut sequence = EventSequence::new(sm, get_state);

        // Generate a valid partial signature from a non-assignee operator
        let first_partial =
            signers[TEST_NON_ASSIGNEE_IDX as usize].sign(&key_agg_ctx, 0, &agg_nonce, message);

        // Generate a random (different) partial signature
        let duplicate_partial = generate_partial_signature();

        let first_event = DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
            partial_signature: first_partial,
            operator_idx: TEST_NON_ASSIGNEE_IDX,
        });
        let duplicate_event = DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
            partial_signature: duplicate_partial,
            operator_idx: TEST_NON_ASSIGNEE_IDX,
        });

        sequence.process(test_deposit_sm_cfg(), first_event);
        sequence.assert_no_errors();
        // Second submission with different signature but same operator - should fail with Duplicate
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
    fn test_invalid_operator_idx_in_payout_partial_received() {
        let (state, _, _, _, _, _, _) = create_payout_partial_test_setup(TEST_ASSIGNEE);

        let sm = create_sm(state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process PayoutPartialReceived with invalid operator idx
        let partial_sig = generate_partial_signature();
        let event = DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
            partial_signature: partial_sig,
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

    /// tests that invalid partial signature is rejected with Rejected error
    #[test]
    fn test_payout_partial_received_invalid_signature() {
        let (state, _, _, _, _, _, _) = create_payout_partial_test_setup(TEST_ASSIGNEE);

        // Generate an invalid/random partial signature
        let invalid_partial = generate_partial_signature();

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: state,
            event: DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
                partial_signature: invalid_partial,
                operator_idx: TEST_NON_ASSIGNEE_IDX,
            }),
            expected_error: |e| {
                matches!(
                    e,
                    DSMError::Rejected { reason, .. }
                    if reason == "Partial Signature Verification Failed"
                )
            },
        });
    }

    /// tests that all states except PayoutNoncesCollected should reject PayoutPartialReceived event
    #[test]
    fn test_payout_partial_received_invalid_from_other_states() {
        let desc = random_p2tr_desc();
        let cooperative_payout_tx = test_payout_txn(desc.clone());

        let partial_sig = generate_partial_signature();

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
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                payout_nonces: BTreeMap::new(),
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
                event: DepositEvent::PayoutPartialReceived(PayoutPartialReceivedEvent {
                    partial_signature: partial_sig,
                    operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
                }),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }
}
