//! Unit Tests for process_new_block
#[cfg(test)]
mod tests {
    use bitcoin::{OutPoint, Txid, hashes::Hash};

    use crate::{
        deposit::{
            errors::DSMError,
            events::{DepositEvent, NewBlockEvent, PayoutConfirmedEvent},
            state::DepositState,
            tests::*,
        },
        signals::{DepositSignal, DepositToGraph},
        testing::fixtures::*,
    };

    #[test]
    fn test_new_block_updates_height_in_deposited() {
        let state = DepositState::Deposited {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let block_height = LATER_BLOCK_HEIGHT;

        let mut sm = create_sm(state);
        let result = sm.process_new_block(NewBlockEvent { block_height });

        assert!(result.is_ok());
        assert_eq!(
            sm.state(),
            &DepositState::Deposited {
                last_block_height: LATER_BLOCK_HEIGHT
            }
        );
    }

    #[test]
    fn test_new_block_triggers_cooperative_timeout() {
        const FULFILLMENT_HEIGHT: u64 = INITIAL_BLOCK_HEIGHT;
        let state = DepositState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: Txid::all_zeros(),
            fulfillment_height: FULFILLMENT_HEIGHT,
            cooperative_payout_deadline: FULFILLMENT_HEIGHT
                + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
        };

        let block_height =
            FULFILLMENT_HEIGHT + test_deposit_sm_cfg().cooperative_payout_timeout_blocks();

        let mut sm = create_sm(state);
        let result = sm.process_new_block(NewBlockEvent { block_height });

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
        assert_eq!(
            sm.state(),
            &DepositState::CooperativePathFailed {
                last_block_height: block_height,
                assignee: TEST_ASSIGNEE,
            }
        );

        // Check signal was emitted
        let output = result.unwrap();
        assert_eq!(output.signals.len(), 1);
        assert!(matches!(
            output.signals[0],
            DepositSignal::ToGraph(DepositToGraph::CooperativePayoutFailed { .. })
        ));
    }

    /// Tests that Assigned state reverts to Deposited when fulfillment deadline expires
    #[test]
    fn test_new_block_reverts_assigned_to_deposited_when_deadline_exceeded() {
        let deadline = INITIAL_BLOCK_HEIGHT + 10;
        let block_height_after_deadline = deadline + 1;

        let state = DepositState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            deadline,
            recipient_desc: random_p2tr_desc(),
        };

        let mut sm = create_sm(state);
        let result = sm.process_new_block(NewBlockEvent {
            block_height: block_height_after_deadline,
        });

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
        assert_eq!(
            sm.state(),
            &DepositState::Deposited {
                last_block_height: block_height_after_deadline
            }
        );
    }

    /// Tests that Assigned state reverts to Deposited when fulfillment deadline is reached
    #[test]
    fn test_new_block_reverts_assigned_to_deposited_when_deadline_reached() {
        let deadline = INITIAL_BLOCK_HEIGHT + 10;

        let state = DepositState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            deadline,
            recipient_desc: random_p2tr_desc(),
        };

        let mut sm = create_sm(state);
        let result = sm.process_new_block(NewBlockEvent {
            block_height: deadline,
        });

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
        assert_eq!(
            sm.state(),
            &DepositState::Deposited {
                last_block_height: deadline
            }
        );
    }

    /// Tests that Assigned state stays in Assigned when deadline has not expired
    #[test]
    fn test_new_block_keeps_assigned_when_deadline_not_exceeded() {
        let deadline = LATER_BLOCK_HEIGHT;
        let block_height_before_deadline = deadline - 1;

        let recipient_desc = random_p2tr_desc();
        let state = DepositState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            deadline,
            recipient_desc: recipient_desc.clone(),
        };

        let mut sm = create_sm(state);
        let result = sm.process_new_block(NewBlockEvent {
            block_height: block_height_before_deadline,
        });

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
        assert_eq!(
            sm.state(),
            &DepositState::Assigned {
                last_block_height: block_height_before_deadline,
                assignee: TEST_ASSIGNEE,
                deadline,
                recipient_desc,
            }
        );
    }

    #[test]
    fn test_new_block_rejects_in_terminal_states() {
        let block_height = LATER_BLOCK_HEIGHT;

        for terminal_state in [DepositState::Spent, DepositState::Aborted] {
            let mut sm = create_sm(terminal_state.clone());
            let result = sm.process_new_block(NewBlockEvent { block_height });

            assert!(
                matches!(result, Err(DSMError::Rejected { .. })),
                "Terminal state {:?} should reject new block with Rejected error (event is not relevant in terminal state)",
                terminal_state
            );
        }
    }

    #[test]
    fn test_payout_confirmed_duplicate_in_spent() {
        let tx = test_payout_tx(OutPoint::default());

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: DepositState::Spent,
            event: DepositEvent::PayoutConfirmed(PayoutConfirmedEvent { tx }),
            expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
        });
    }
}
