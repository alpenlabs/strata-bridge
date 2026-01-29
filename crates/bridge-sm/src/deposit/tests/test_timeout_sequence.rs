//! Unit Tests for process_new_block
#[cfg(test)]
mod tests {
    use bitcoin::{Txid, hashes::Hash};

    use crate::{
        deposit::{
            events::{DepositEvent, NewBlockEvent},
            state::DepositState,
            tests::*,
        },
        signals::{DepositSignal, DepositToGraph},
        testing::transition::*,
    };

    #[test]
    fn test_cooperative_timeout_sequence() {
        const FULFILLMENT_HEIGHT: u64 = INITIAL_BLOCK_HEIGHT;
        let initial_state = DepositState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: Txid::all_zeros(),
            fulfillment_height: FULFILLMENT_HEIGHT,
            cooperative_payout_deadline: FULFILLMENT_HEIGHT
                + test_bridge_cfg().cooperative_payout_timeout_blocks(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        // Process blocks up to and past timeout
        let timeout_height =
            FULFILLMENT_HEIGHT + test_bridge_cfg().cooperative_payout_timeout_blocks();
        for height in (FULFILLMENT_HEIGHT + 1)..=timeout_height {
            seq.process(DepositEvent::NewBlock(NewBlockEvent {
                block_height: height,
            }));
        }

        seq.assert_no_errors();

        // Should transition to CooperativePathFailed at timeout_height
        assert_eq!(
            seq.state(),
            &DepositState::CooperativePathFailed {
                last_block_height: timeout_height
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
}
