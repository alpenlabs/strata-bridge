//! Property-based tests for the Deposit State Machine.
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::{
        deposit::state::tests::*, prop_deterministic, prop_no_silent_acceptance,
        prop_terminal_states_reject,
    };

    // Property: State machine is deterministic for the implemented states and events space
    prop_deterministic!(
        DepositSM,
        create_sm,
        get_state,
        any::<DepositState>(),
        arb_handled_events() /* TODO: (@Rajil1213) replace with any::<DepositEvent>() once all
                              * STFs are implemented */
    );

    // Property: No silent acceptance
    prop_no_silent_acceptance!(
        DepositSM,
        create_sm,
        get_state,
        any::<DepositState>(),
        arb_handled_events() /* TODO: (@Rajil1213) replace with any::<DepositEvent>() once all
                              * STFs are implemented */
    );

    // Property: Terminal states reject all events
    prop_terminal_states_reject!(
        DepositSM,
        create_sm,
        arb_terminal_state(),
        arb_handled_events() /* TODO: (@Rajil1213) replace with any::<DepositEvent>() once all
                              * STFs are implemented */
    );
}
