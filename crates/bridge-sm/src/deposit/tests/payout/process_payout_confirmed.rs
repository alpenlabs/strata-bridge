//! Unit Tests for process_payout_confirmed
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::OutPoint;

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
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
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
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
            },
            event: payout_confirmed_event(test_deposit_outpoint()),
            expected_state: DepositState::Spent {
                fulfillment_txid: Some(fulfillment_txid),
                assignee: Some(TEST_ASSIGNEE),
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
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
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
                cooperative_payout_tx: test_cooperative_payout_txn(desc),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
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
            },
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
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

    /// Tests that all states apart from Deposited, PayoutNoncesCollected,
    /// CooperativePathFailed, and Spent should NOT accept the PayoutConfirmed event.
    #[test]
    fn test_payout_confirmed_invalid_from_other_states() {
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
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                fulfillment_height: LATER_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT
                    + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx: test_cooperative_payout_txn(desc),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::Aborted,
        ];

        for state in invalid_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: payout_confirmed_event(test_deposit_outpoint()),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }
}
