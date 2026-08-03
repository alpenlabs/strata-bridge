//! Unit Tests for process_sweep_partial_received
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::{AggNonce, PubNonce};
    use strata_bridge_tx_graph::transactions::sweep::SweepTx;

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, SweepPartialReceivedEvent},
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    /// Helper to create test setup for sweep partial tests.
    /// Returns (state, signers, key_agg_ctx, agg_nonce, message, sweep_tx).
    fn create_sweep_partial_test_setup() -> (
        DepositState,
        Vec<TestMusigSigner>,
        musig2::KeyAggContext,
        AggNonce,
        Message,
        SweepTx,
    ) {
        let signers = test_operator_signers();

        // Build sweep tx and get signing info
        let sweep_tx = test_sweep_txn(random_p2tr_desc());
        let (key_agg_ctx, message) = get_sweep_signing_info(&sweep_tx, &signers);

        // Generate nonces (counter=0 for this signing round)
        let agg_pubkey = key_agg_ctx.aggregated_pubkey();
        let nonce_counter = 0u64;
        let nonces: BTreeMap<OperatorIdx, PubNonce> = signers
            .iter()
            .map(|s| (s.operator_idx(), s.pubnonce(agg_pubkey, nonce_counter)))
            .collect();
        let agg_nonce = AggNonce::sum(nonces.values().cloned());

        let state = DepositState::SweepNoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            sweep_tx: sweep_tx.clone(),
            sweep_agg_nonce: agg_nonce.clone(),
            sweep_nonces: nonces,
            sweep_partials: BTreeMap::new(),
        };

        (state, signers, key_agg_ctx, agg_nonce, message, sweep_tx)
    }

    /// tests partial collection: first partial received, stays in SweepNoncesCollected state
    #[test]
    fn test_sweep_partial_received_partial_collection() {
        let (state, signers, key_agg_ctx, agg_nonce, message, sweep_tx) =
            create_sweep_partial_test_setup();

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::SweepNoncesCollected { sweep_nonces, .. } = &state {
            sweep_nonces.clone()
        } else {
            panic!("Expected SweepNoncesCollected state");
        };

        // Generate a valid partial signature from an arbitrary operator
        let nonce_counter = 0u64;
        let partial_sig = signers[TEST_ARBITRARY_OPERATOR_IDX as usize].sign(
            &key_agg_ctx,
            nonce_counter,
            &agg_nonce,
            message,
        );

        let mut expected_partials = BTreeMap::new();
        expected_partials.insert(TEST_ARBITRARY_OPERATOR_IDX, partial_sig);

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
                partial_signature: partial_sig,
                operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
            }),
            expected_state: DepositState::SweepNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx,
                sweep_agg_nonce: agg_nonce,
                sweep_nonces: nonces,
                sweep_partials: expected_partials,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests all partials collected - every operator emits the PublishSweep duty with all N
    /// partials (unlike the cooperative payout, which waits for N-1 and only the assignee
    /// publishes)
    #[test]
    fn test_sweep_partial_received_all_collected() {
        let (mut state, signers, key_agg_ctx, agg_nonce, message, sweep_tx) =
            create_sweep_partial_test_setup();

        // Extract nonces from state for expected state construction
        let nonces = if let DepositState::SweepNoncesCollected { sweep_nonces, .. } = &state {
            sweep_nonces.clone()
        } else {
            panic!("Expected SweepNoncesCollected state");
        };

        // Generate partial signatures for *all* operators
        let nonce_counter = 0u64;
        let all_partials: BTreeMap<OperatorIdx, _> = signers
            .iter()
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
        if let DepositState::SweepNoncesCollected { sweep_partials, .. } = &mut state {
            *sweep_partials = initial_partials;
        } else {
            panic!("Expected SweepNoncesCollected state");
        }

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
                partial_signature: incoming_partial,
                operator_idx: incoming_idx,
            }),
            expected_state: DepositState::SweepNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: sweep_tx.clone(),
                sweep_agg_nonce: agg_nonce.clone(),
                sweep_nonces: nonces,
                sweep_partials: all_partials.clone(),
            },
            expected_duties: vec![DepositDuty::PublishSweep {
                deposit_outpoint: test_deposit_outpoint(),
                agg_nonce,
                collected_partials: all_partials,
                sweep_tx: Box::new(sweep_tx),
                ordered_pubkeys: test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX)
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect(),
            }],
            expected_signals: vec![],
        });
    }

    /// tests duplicate detection: same operator sends a partial signature twice
    #[test]
    fn test_sweep_partial_received_duplicate() {
        let (state, signers, key_agg_ctx, agg_nonce, message, _) =
            create_sweep_partial_test_setup();

        let sm = create_sm(state);
        let mut sequence = EventSequence::new(sm, get_state);

        // Generate a valid partial signature
        let partial_sig = signers[TEST_ARBITRARY_OPERATOR_IDX as usize].sign(
            &key_agg_ctx,
            0,
            &agg_nonce,
            message,
        );

        let event = DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
            partial_signature: partial_sig,
            operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
        });

        sequence.process(test_deposit_sm_cfg(), event.clone());
        sequence.assert_no_errors();
        // Second submission from the same operator - should fail with Duplicate
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

    /// tests that an invalid partial signature is rejected with Rejected error
    #[test]
    fn test_sweep_partial_received_invalid_signature() {
        let (state, _, _, _, _, _) = create_sweep_partial_test_setup();

        // Generate an invalid/random partial signature
        let invalid_partial = generate_partial_signature();

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: state,
            event: DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
                partial_signature: invalid_partial,
                operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
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

    /// tests that invalid operator index is rejected
    #[test]
    fn test_invalid_operator_idx_in_sweep_partial_received() {
        let (state, _, _, _, _, _) = create_sweep_partial_test_setup();

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: state,
            event: DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
                partial_signature: generate_partial_signature(),
                operator_idx: u32::MAX,
            }),
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }

    /// tests that all states except SweepNoncesCollected reject SweepPartialReceived
    #[test]
    fn test_sweep_partial_received_invalid_from_other_states() {
        let partial_sig = generate_partial_signature();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_nonces: BTreeMap::new(),
            },
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
            },
            DepositState::Aborted,
        ];

        for state in invalid_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
                    partial_signature: partial_sig,
                    operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
                }),
                // Peer-facing errors are softened to Rejected by the state machine.
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            });
        }
    }
}
