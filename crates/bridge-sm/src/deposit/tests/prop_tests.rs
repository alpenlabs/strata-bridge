//! Property-based tests for the Deposit State Machine.
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::{
        deposit::tests::*,
        prop_deterministic, prop_no_silent_acceptance, prop_terminal_states_ignore_ticks,
        prop_terminal_states_reject,
        signals::{DepositSignal, DepositToGraph},
        testing::transition::EventSequence,
    };

    // Property: State machine is deterministic for the implemented states and events space
    prop_deterministic!(
        DepositSM,
        create_sm,
        get_state,
        test_deposit_sm_cfg(),
        any::<DepositState>(),
        any::<DepositEvent>()
    );

    // Property: No silent acceptance
    prop_no_silent_acceptance!(
        DepositSM,
        create_sm,
        get_state,
        test_deposit_sm_cfg(),
        any::<DepositState>(),
        prop_oneof![arb_stf_events(), arb_nag_received_events()]
    );

    // Property: Terminal states reject all events
    prop_terminal_states_reject!(
        DepositSM,
        create_sm,
        get_state,
        test_deposit_sm_cfg(),
        arb_terminal_state(),
        prop_oneof![arb_stf_events(), arb_nag_received_events()]
    );

    // Property: Terminal states ignore ticks
    prop_terminal_states_ignore_ticks!(
        DepositSM,
        create_sm,
        get_state,
        test_deposit_sm_cfg(),
        arb_terminal_state(),
        arb_tick_events()
    );

    #[derive(Debug, Clone, Copy)]
    enum PayoutStep {
        Partial,
        Block,
        Retry,
    }

    // Property: Exactly one of the cooperative payout and the claim path is activated, whatever the
    // order in which the payout partials and the deadline arrive
    proptest! {
        #[test]
        fn cooperative_payout_and_claim_activation_are_exclusive(
            steps in Just(vec![
                PayoutStep::Partial,
                PayoutStep::Partial,
                PayoutStep::Block,
                PayoutStep::Block,
                PayoutStep::Block,
                PayoutStep::Retry,
                PayoutStep::Retry,
            ])
            .prop_shuffle()
        ) {
            let (initial_state, partials) = payout_signing_round(TEST_POV_IDX);
            let mut partials = partials.into_iter();
            let mut block_heights = (LATER_BLOCK_HEIGHT - 1)..;
            let mut seq = EventSequence::new(create_sm(initial_state), get_state);

            for step in steps {
                let event = match step {
                    PayoutStep::Partial => partials.next().expect("one partial per step"),
                    PayoutStep::Block => DepositEvent::NewBlock(NewBlockEvent {
                        block_height: block_heights.next().expect("unbounded range"),
                    }),
                    PayoutStep::Retry => DepositEvent::RetryTick(RetryTickEvent),
                };
                seq.process(test_deposit_sm_cfg(), event);
            }

            let payout_published = seq
                .all_duties()
                .iter()
                .any(|duty| matches!(duty, DepositDuty::PublishPayout { .. }));
            let claim_activated = seq.all_signals().iter().any(|signal| {
                matches!(
                    signal,
                    DepositSignal::ToGraph(DepositToGraph::CooperativePayoutFailed { .. })
                )
            });
            prop_assert_ne!(payout_published, claim_activated);
        }
    }
}
