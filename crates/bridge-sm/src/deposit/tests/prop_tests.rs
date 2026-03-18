//! Property-based tests for the Deposit State Machine.
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::{
        deposit::tests::*, prop_deterministic, prop_no_silent_acceptance,
        prop_terminal_states_reject,
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
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2674>
        // Replace `arb_handled_events()` with `any::<DepositEvent>()` once all STFs are
        // implemented.
        arb_handled_events()
    );

    // Property: Terminal states reject all events
    prop_terminal_states_reject!(
        DepositSM,
        create_sm,
        test_deposit_sm_cfg(),
        arb_terminal_state(),
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2674>
        // Replace `arb_handled_events()` with `any::<DepositEvent>()` once all STFs are
        // implemented.
        arb_handled_events()
    );
}
