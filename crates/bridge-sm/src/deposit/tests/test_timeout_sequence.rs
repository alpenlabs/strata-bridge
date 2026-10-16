//! Unit Tests for process_new_block
#[cfg(test)]
mod tests {

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, NewBlockEvent, RetryTickEvent},
            state::DepositState,
            tests::*,
        },
        signals::{DepositSignal, DepositToGraph},
        testing::transition::*,
    };

    #[test]
    fn test_cooperative_timeout_sequence() {
        const FULFILLMENT_HEIGHT: u64 = INITIAL_BLOCK_HEIGHT;
        let fulfillment_txid = generate_txid();
        let initial_state = DepositState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid,
            fulfillment_height: FULFILLMENT_HEIGHT,
            cooperative_payout_deadline: FULFILLMENT_HEIGHT
                + test_deposit_sm_cfg().cooperative_payout_timeout_blocks(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        // Process blocks up to and past timeout
        let timeout_height =
            FULFILLMENT_HEIGHT + test_deposit_sm_cfg().cooperative_payout_timeout_blocks();
        for height in (FULFILLMENT_HEIGHT + 1)..=timeout_height {
            seq.process(
                test_deposit_sm_cfg(),
                DepositEvent::NewBlock(NewBlockEvent {
                    block_height: height,
                }),
            );
        }

        seq.assert_no_errors();

        // Should transition to CooperativePathFailed at timeout_height
        assert_eq!(
            seq.state(),
            &DepositState::CooperativePathFailed {
                last_block_height: timeout_height,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid,
            }
        );

        // Check that cooperative failure signal was emitted
        let signals = seq.all_signals();
        assert!(
            signals.iter().any(|s| matches!(
                s,
                DepositSignal::ToGraph(DepositToGraph::CooperativePayoutFailed { .. })
            )),
            "Should emit CooperativePayoutFailed signal"
        );
    }

    #[test]
    fn test_cooperative_path_survives_deadline_once_all_payout_partials_collected() {
        let (initial_state, partials) = payout_signing_round(TEST_POV_IDX);
        let mut seq = EventSequence::new(create_sm(initial_state), get_state);

        for partial in partials {
            seq.process(test_deposit_sm_cfg(), partial);
        }
        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::NewBlock(NewBlockEvent {
                block_height: LATER_BLOCK_HEIGHT,
            }),
        );
        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::RetryTick(RetryTickEvent),
        );

        seq.assert_no_errors();
        assert!(matches!(
            seq.state(),
            DepositState::PayoutNoncesCollected { .. }
        ));
        assert!(seq.all_signals().is_empty());
        assert_eq!(
            seq.all_duties()
                .iter()
                .filter(|duty| matches!(duty, DepositDuty::PublishPayout { .. }))
                .count(),
            2,
            "final partial and retry tick should both emit PublishPayout"
        );
    }

    #[test]
    fn test_cooperative_timeout_rejects_payout_partial_received_after_deadline() {
        let (initial_state, partials) = payout_signing_round(TEST_POV_IDX);
        let [first_partial, last_partial] = partials.try_into().expect("two non-assignees");
        let mut seq = EventSequence::new(create_sm(initial_state), get_state);

        seq.process(test_deposit_sm_cfg(), first_partial);
        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::NewBlock(NewBlockEvent {
                block_height: LATER_BLOCK_HEIGHT,
            }),
        );
        seq.process(test_deposit_sm_cfg(), last_partial);
        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::RetryTick(RetryTickEvent),
        );

        assert!(matches!(
            seq.state(),
            DepositState::CooperativePathFailed { .. }
        ));
        assert!(matches!(
            seq.all_errors().as_slice(),
            [DSMError::Rejected { .. }]
        ));
        assert!(seq.all_duties().is_empty());
        assert!(matches!(
            seq.all_signals().as_slice(),
            [DepositSignal::ToGraph(
                DepositToGraph::CooperativePayoutFailed { .. }
            )]
        ));
    }
}
