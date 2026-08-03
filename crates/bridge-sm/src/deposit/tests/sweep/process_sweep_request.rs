//! Unit Tests for process_sweep_request
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::deposit::{
        duties::DepositDuty,
        errors::DSMError,
        events::{DepositEvent, SweepRequestedEvent},
        state::DepositState,
        tests::*,
    };

    /// tests that a sweep request from Deposited builds the sweep tx and emits the nonce duty
    #[test]
    fn test_sweep_request_from_deposited() {
        let desc = random_p2tr_desc();
        let sweep_tx = test_sweep_txn(desc.clone());

        let sweep_sighash = sweep_tx
            .signing_info()
            .first()
            .expect("sweep transaction must have signing info")
            .sighash;

        test_deposit_transition(DepositTransition {
            from_state: DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            event: DepositEvent::SweepRequested(SweepRequestedEvent {
                safe_harbour_desc: desc,
            }),
            expected_state: DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx,
                sweep_nonces: BTreeMap::new(),
            },
            expected_duties: vec![DepositDuty::PublishSweepNonce {
                deposit_idx: TEST_DEPOSIT_IDX,
                deposit_outpoint: test_deposit_outpoint(),
                ordered_pubkeys: test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX)
                    .btc_keys()
                    .into_iter()
                    .map(|pk| pk.x_only_public_key().0)
                    .collect(),
                tweak: TaprootTweak::Key { tweak: None },
                sweep_sighash,
            }],
            expected_signals: vec![],
        });
    }

    /// tests that a re-emitted sweep request is a duplicate once the sweep is in progress or the
    /// deposit is spent
    #[test]
    fn test_sweep_request_duplicate_in_sweep_and_spent_states() {
        let desc = random_p2tr_desc();

        let duplicate_states = [
            DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(desc.clone()),
                sweep_nonces: BTreeMap::new(),
            },
            DepositState::SweepNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(desc.clone()),
                sweep_agg_nonce: generate_agg_nonce(),
                sweep_nonces: BTreeMap::new(),
                sweep_partials: BTreeMap::new(),
            },
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
            },
        ];

        for state in duplicate_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: DepositEvent::SweepRequested(SweepRequestedEvent {
                    safe_harbour_desc: desc.clone(),
                }),
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            });
        }
    }

    /// tests that a sweep request from every assigned/mid-payout live-UTXO state builds the same
    /// sweep tx as from Deposited, discarding the withdrawal-progress fields
    #[test]
    fn test_sweep_request_from_withdrawal_states_discards_progress() {
        let desc = random_p2tr_desc();

        let source_states = [
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: random_p2tr_desc(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx: test_cooperative_payout_txn(desc.clone()),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                cooperative_payout_tx: test_cooperative_payout_txn(desc.clone()),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
            },
        ];

        for from_state in source_states {
            let sweep_tx = test_sweep_txn(desc.clone());
            let sweep_sighash = sweep_tx
                .signing_info()
                .first()
                .expect("sweep transaction must have signing info")
                .sighash;

            test_deposit_transition(DepositTransition {
                from_state,
                event: DepositEvent::SweepRequested(SweepRequestedEvent {
                    safe_harbour_desc: desc.clone(),
                }),
                expected_state: DepositState::SweepNoncesPending {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    sweep_tx,
                    sweep_nonces: BTreeMap::new(),
                },
                expected_duties: vec![DepositDuty::PublishSweepNonce {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deposit_outpoint: test_deposit_outpoint(),
                    ordered_pubkeys: test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX)
                        .btc_keys()
                        .into_iter()
                        .map(|pk| pk.x_only_public_key().0)
                        .collect(),
                    tweak: TaprootTweak::Key { tweak: None },
                    sweep_sighash,
                }],
                expected_signals: vec![],
            });
        }
    }

    /// tests that the pre-deposit states and Aborted (no live deposit UTXO) reject SweepRequested
    #[test]
    fn test_sweep_request_invalid_from_other_states() {
        let desc = random_p2tr_desc();

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
        ];

        for state in invalid_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: DepositEvent::SweepRequested(SweepRequestedEvent {
                    safe_harbour_desc: desc.clone(),
                }),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }
}
