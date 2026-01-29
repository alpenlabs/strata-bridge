//! Unit Tests for process_new_block
#[cfg(test)]
mod tests {
    use bitcoin::{OutPoint, Txid, hashes::Hash};

    use crate::{
        deposit::{
            errors::DSMError,
            events::{DepositEvent, NewBlockEvent, PayoutConfirmedEvent},
            machine::{COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS, DepositSM},
            state::DepositState,
            tests::*,
        },
        signals::{DepositSignal, DepositToGraph},
        testing::{fixtures::*, transition::*},
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
            cooperative_payout_deadline: FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
        };

        let block_height = FULFILLMENT_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS;

        let mut sm = create_sm(state);
        let result = sm.process_new_block(NewBlockEvent { block_height });

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
        assert_eq!(
            sm.state(),
            &DepositState::CooperativePathFailed {
                last_block_height: block_height
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

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            InvalidTransition {
                from_state: DepositState::Spent,
                event: DepositEvent::PayoutConfirmed(PayoutConfirmedEvent { tx }),
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            },
        );
    }
}
