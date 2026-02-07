//! Property-based testing macros for state machines.
//!
//! This module provides macros for testing invariant properties that should hold
//! across arbitrary inputs. These use proptest to generate random test cases and
//! verify that fundamental properties of state machines are maintained.

/// Property: State machines should be deterministic.
///
/// Given the same initial state and event, the state machine should
/// always produce the same result.
///
/// # Arguments
/// * `$sm_type` - The state machine type
/// * `$create_fn` - Function to create SM from state: `Fn(State) -> SM`
/// * `$get_state_fn` - Function to get state from SM: `Fn(&SM) -> &State`
/// * `$config` - Configuration to pass to `process_event`
/// * `$state_strategy` - Proptest strategy for generating states
/// * `$event_strategy` - Proptest strategy for generating events
#[macro_export]
macro_rules! prop_deterministic {
    ($sm_type:ty, $create_fn:expr, $get_state_fn:expr, $config:expr, $state_strategy:expr, $event_strategy:expr) => {
        proptest::proptest! {
            #[test]
            fn state_machine_is_deterministic(
                state in $state_strategy,
                event in $event_strategy,
            ) {
                use $crate::state_machine::StateMachine;

                let mut sm1 = $create_fn(state.clone());
                let mut sm2 = $create_fn(state);

                let result1 = sm1.process_event($config, event.clone());
                let result2 = sm2.process_event($config, event);

                match (result1, result2) {
                    (Ok(out1), Ok(out2)) => {
                        proptest::prop_assert_eq!($get_state_fn(&sm1), $get_state_fn(&sm2));
                        proptest::prop_assert_eq!(out1.duties, out2.duties);
                        proptest::prop_assert_eq!(out1.signals, out2.signals);
                    }
                    (Err(_), Err(_)) => {
                        // Both failed - that's consistent
                    }
                    _ => {
                        proptest::prop_assert!(false, "Inconsistent results: one succeeded, one failed");
                    }
                }
            }
        }
    };
}

/// Property: Terminal states should reject all events.
///
/// Use this macro to test that your terminal states properly reject
/// all events with appropriate errors.
///
/// # Arguments
/// * `$sm_type` - The state machine type
/// * `$create_fn` - Function to create SM from state: `Fn(State) -> SM`
/// * `$config` - Configuration to pass to `process_event`
/// * `$terminal_states` - Proptest strategy for generating terminal states
/// * `$event_strategy` - Proptest strategy for generating events
#[macro_export]
macro_rules! prop_terminal_states_reject {
    ($sm_type:ty, $create_fn:expr, $config:expr, $terminal_states:expr, $event_strategy:expr) => {
        proptest::proptest! {
            #[test]
            fn terminal_states_reject_all_events(
                terminal_state in $terminal_states,
                event in $event_strategy,
            ) {
                use $crate::state_machine::StateMachine;

                let mut sm = $create_fn(terminal_state);
                let result = sm.process_event($config, event);

                proptest::prop_assert!(result.is_err(), "Terminal state should reject event");
                proptest::prop_assert!(
                    result.is_err(),
                    "Terminal states should return error, got: {:?}",
                    result
                );
            }
        }
    };
}

/// Property: Events must either transition state or produce error.
///
/// State machines should never silently accept events without changing state.
///
/// # Arguments
/// * `$sm_type` - The state machine type
/// * `$create_fn` - Function to create SM from state: `Fn(State) -> SM`
/// * `$config` - Configuration to pass to `process_event`
/// * `$get_state_fn` - Function to get state from SM: `Fn(&SM) -> &State`
/// * `$state_strategy` - Proptest strategy for generating states
/// * `$event_strategy` - Proptest strategy for generating events
#[macro_export]
macro_rules! prop_no_silent_acceptance {
    ($sm_type:ty, $create_fn:expr, $get_state_fn:expr, $config:expr, $state_strategy:expr, $event_strategy:expr) => {
        proptest::proptest! {
            #[test]
            fn events_transition_or_error(
                state in $state_strategy,
                event in $event_strategy,
            ) {
                use $crate::state_machine::StateMachine;

                let initial_state = state.clone();
                let mut sm = $create_fn(state);

                let result = sm.process_event($config, event);
                let final_state = $get_state_fn(&sm).clone();

                match result {
                    Ok(output) => {
                        // If successful, state must change OR duties/signals must be emitted
                        let state_changed = initial_state != final_state;
                        let has_output = !output.duties.is_empty() || !output.signals.is_empty();

                        proptest::prop_assert!(
                            state_changed || has_output,
                            "Event was accepted but nothing happened (no state change, duties, or signals)"
                        );
                    }
                    Err(_) => {
                        // Error is fine, but state should not change
                        proptest::prop_assert_eq!(
                            &initial_state,
                            &final_state,
                            "State changed despite error"
                        );
                    }
                }
            }
        }
    };
}
