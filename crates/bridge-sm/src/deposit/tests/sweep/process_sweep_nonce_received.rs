//! Unit Tests for process_sweep_nonce_received
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::{AggNonce, PubNonce};

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, SweepNonceReceivedEvent},
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    /// tests partial collection: first nonce received, stays in SweepNoncesPending state
    #[test]
    fn test_sweep_nonce_received_partial_collection() {
        let sweep_tx = test_sweep_txn(random_p2tr_desc());
        let nonce = generate_pubnonce();

        let mut expected_nonces = BTreeMap::new();
        expected_nonces.insert(TEST_ARBITRARY_OPERATOR_IDX, nonce.clone());

        test_deposit_transition(DepositTransition {
            from_state: DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: sweep_tx.clone(),
                sweep_nonces: BTreeMap::new(),
            },
            event: DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
                sweep_nonce: nonce,
                operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
            }),
            expected_state: DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx,
                sweep_nonces: expected_nonces,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests all nonces collected - every operator emits the PublishSweepPartial duty
    /// (no assignee asymmetry, unlike the cooperative payout)
    #[test]
    fn test_sweep_nonce_received_all_collected() {
        let sweep_tx = test_sweep_txn(random_p2tr_desc());

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

        // Compute expected aggregated nonce
        let expected_agg_nonce = AggNonce::sum(all_nonces.values().cloned());

        let sweep_sighash = sweep_tx
            .signing_info()
            .first()
            .expect("sweep transaction must have signing info")
            .sighash;

        test_deposit_transition(DepositTransition {
            from_state: DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: sweep_tx.clone(),
                sweep_nonces: initial_nonces,
            },
            event: DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
                sweep_nonce: incoming_nonce,
                operator_idx: incoming_idx,
            }),
            expected_state: DepositState::SweepNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx,
                sweep_agg_nonce: expected_agg_nonce.clone(),
                sweep_nonces: all_nonces,
                sweep_partials: BTreeMap::new(),
            },
            expected_duties: vec![DepositDuty::PublishSweepPartial {
                deposit_idx: TEST_DEPOSIT_IDX,
                deposit_outpoint: test_deposit_outpoint(),
                sweep_sighash,
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

    /// tests duplicate detection: same operator sends a nonce twice
    #[test]
    fn test_sweep_nonce_received_duplicate() {
        let initial_state = DepositState::SweepNoncesPending {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            sweep_tx: test_sweep_txn(random_p2tr_desc()),
            sweep_nonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut sequence = EventSequence::new(sm, get_state);

        let nonce_event = DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
            sweep_nonce: generate_pubnonce(),
            operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
        });

        sequence.process(test_deposit_sm_cfg(), nonce_event.clone());
        sequence.assert_no_errors();
        // Second submission from the same operator - should fail with Duplicate
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

    /// tests that invalid operator index is rejected
    #[test]
    fn test_invalid_operator_idx_in_sweep_nonce_received() {
        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_nonces: BTreeMap::new(),
            },
            event: DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
                sweep_nonce: generate_pubnonce(),
                operator_idx: u32::MAX,
            }),
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }

    /// tests that all states except SweepNoncesPending reject SweepNonceReceived
    #[test]
    fn test_sweep_nonce_received_invalid_from_other_states() {
        let nonce = generate_pubnonce();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::SweepNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_agg_nonce: generate_agg_nonce(),
                sweep_nonces: BTreeMap::new(),
                sweep_partials: BTreeMap::new(),
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
                event: DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
                    sweep_nonce: nonce.clone(),
                    operator_idx: TEST_ARBITRARY_OPERATOR_IDX,
                }),
                // Peer-facing errors are softened to Rejected by the state machine.
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            });
        }
    }
}
