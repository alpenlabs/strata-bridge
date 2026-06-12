//! Unit Tests for process_assignment
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::{Txid, hashes::Hash};

    use crate::deposit::{
        duties::DepositDuty,
        errors::DSMError,
        events::{DepositEvent, WithdrawalAssignedEvent},
        state::DepositState,
        tests::*,
    };

    /// tests correct transition from Deposited to Assigned state when Assignment event
    /// is received and POV operator is the assignee (should emit FulfillWithdrawalRequest duty).
    #[test]
    fn test_assignment_from_deposited_pov_is_assignee() {
        let desc = random_p2tr_desc();

        let state = DepositState::Deposited {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            }),
            expected_state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            },
            expected_duties: vec![DepositDuty::FulfillWithdrawalRequest {
                deposit_idx: TEST_DEPOSIT_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc,
                deposit_amount: TEST_DEPOSIT_AMOUNT,
            }],
            expected_signals: vec![],
        });
    }

    /// tests correct transition from Deposited to Assigned state when Assignment event
    /// is received and POV operator is NOT the assignee (should NOT emit any duty).
    #[test]
    fn test_assignment_from_deposited_pov_is_not_assignee() {
        let desc = random_p2tr_desc();

        let state = DepositState::Deposited {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_NONPOV_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
            }),
            expected_state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests correct re-assignment from Assigned state when Assignment event is received
    /// and POV operator is the new assignee (should emit FulfillWithdrawalRequest duty).
    #[test]
    fn test_reassignment_to_pov() {
        let desc = random_p2tr_desc();

        let state = DepositState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_NONPOV_IDX,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: desc.clone(),
        };

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            }),
            expected_state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            },
            expected_duties: vec![DepositDuty::FulfillWithdrawalRequest {
                deposit_idx: TEST_DEPOSIT_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc,
                deposit_amount: TEST_DEPOSIT_AMOUNT,
            }],
            expected_signals: vec![],
        });
    }

    /// tests correct re-assignment from Assigned state when Assignment event is received
    /// and POV operator is NOT the new assignee (should NOT emit any duty)
    #[test]
    fn test_reassignment_pov_is_not_assignee() {
        let desc = random_p2tr_desc();

        // Start in Assigned state with POV operator
        let state = DepositState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_POV_IDX,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: desc.clone(),
        };

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_NONPOV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            }),
            expected_state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_reassignment_rejected_when_recipient_changes() {
        let original_desc = random_p2tr_desc();
        let changed_desc = random_p2tr_desc();
        assert_ne!(original_desc, changed_desc, "descriptors must differ");

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: original_desc,
            },
            event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: changed_desc,
            }),
            expected_error: |e| {
                matches!(
                    e,
                    DSMError::Rejected { reason, .. }
                    if reason == "recipient descriptor cannot be changed for an existing assignment"
                )
            },
        });
    }

    #[test]
    fn test_reassignment_rejected_when_deadline_decreases() {
        let desc = random_p2tr_desc();

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE,
                recipient_desc: desc.clone(),
            },
            event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                assignee: TEST_POV_IDX,
                deadline: REASSIGNMENT_DEADLINE - 1,
                recipient_desc: desc,
            }),
            expected_error: |e| {
                matches!(
                    e,
                    DSMError::Rejected { reason, .. }
                    if reason == "assignment deadline must not be smaller than the existing deadline"
                )
            },
        });
    }

    /// tests that pre-deposit and terminal states should reject the Assignment event as invalid
    #[test]
    fn test_assignment_invalid_from_other_states() {
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
                event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                    assignee: TEST_ASSIGNEE,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc.clone(),
                }),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }

    /// tests that post-assignment states treat re-delivered Assignment events as duplicates
    #[test]
    fn test_assignment_duplicate_from_post_assignment_states() {
        let desc = random_p2tr_desc();

        let post_assignment_states = [
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
            DepositState::Spent {
                fulfillment_txid: Some(generate_txid()),
                assignee: Some(TEST_ASSIGNEE),
            },
        ];

        for state in post_assignment_states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: DepositEvent::WithdrawalAssigned(WithdrawalAssignedEvent {
                    assignee: TEST_ASSIGNEE,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc.clone(),
                }),
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            });
        }
    }
}
