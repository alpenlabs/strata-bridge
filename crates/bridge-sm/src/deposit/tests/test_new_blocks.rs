//! Unit Tests for process_new_block
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        deposit::{errors::DSMError, events::NewBlockEvent, state::DepositState, tests::*},
        signals::{DepositSignal, DepositToGraph},
        testing::fixtures::*,
    };

    fn payout_nonces_collected_state(signers: &[OperatorIdx]) -> DepositState {
        DepositState::PayoutNoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: generate_txid(),
            cooperative_payout_tx: test_cooperative_payout_txn(random_p2tr_desc()),
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            payout_nonces: BTreeMap::new(),
            payout_aggregated_nonce: generate_agg_nonce(),
            payout_partial_signatures: signers
                .iter()
                .map(|&idx| (idx, generate_partial_signature()))
                .collect(),
        }
    }

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
        let fulfillment_txid = generate_txid();
        let state = DepositState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid,
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
                fulfillment_txid,
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

    #[test]
    fn test_new_block_triggers_cooperative_timeout_with_missing_payout_partials() {
        // Non-assignees are operators 0 and 1.
        for signers in [&[0][..], &[0, TEST_ASSIGNEE]] {
            let mut sm = create_sm(payout_nonces_collected_state(signers));
            let output = sm
                .process_new_block(NewBlockEvent {
                    block_height: LATER_BLOCK_HEIGHT,
                })
                .expect("new block must be accepted");

            assert!(matches!(
                sm.state(),
                DepositState::CooperativePathFailed {
                    last_block_height: LATER_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    ..
                }
            ));
            assert!(matches!(
                output.signals.as_slice(),
                [DepositSignal::ToGraph(
                    DepositToGraph::CooperativePayoutFailed { .. }
                )]
            ));
        }
    }

    #[test]
    fn test_new_block_keeps_cooperative_path_after_deadline_with_all_payout_partials() {
        let mut sm = create_sm(payout_nonces_collected_state(&[0, 1]));
        let block_height = LATER_BLOCK_HEIGHT + 1;
        let output = sm
            .process_new_block(NewBlockEvent { block_height })
            .expect("new block must be accepted");

        assert!(matches!(
            sm.state(),
            DepositState::PayoutNoncesCollected {
                last_block_height,
                ..
            } if *last_block_height == block_height
        ));
        assert!(output.signals.is_empty());
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

        for terminal_state in [
            DepositState::Spent {
                fulfillment_txid: Some(generate_txid()),
                assignee: Some(TEST_ASSIGNEE),
            },
            DepositState::Aborted,
            DepositState::Skipped,
        ] {
            let mut sm = create_sm(terminal_state.clone());
            let result = sm.process_new_block(NewBlockEvent { block_height });

            assert!(
                matches!(result, Err(DSMError::Rejected { .. })),
                "Terminal state {:?} should reject new block with Rejected error (event is not relevant in terminal state)",
                terminal_state
            );
        }
    }
}
