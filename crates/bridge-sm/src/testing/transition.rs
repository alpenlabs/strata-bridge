//! Value-based transition testing helpers.
//!
//! This module provides utilities for testing state machines with specific, concrete values.
//! These helpers make it easy to write declarative tests for individual transitions and
//! sequences of events.

use std::fmt::Debug;

use crate::{
    signals::Signal,
    state_machine::{SMOutput, StateMachine},
};

/// Describes a valid state transition for value-based testing.
///
/// Use this to declaratively specify your state machine's transition table,
/// then use `test_transition` to verify the behavior with concrete values.
#[derive(Debug)]
pub struct Transition<S, E, D, Sig> {
    /// The initial state before the transition
    pub from_state: S,
    /// The event that triggers the transition
    pub event: E,
    /// The expected state after the transition
    pub expected_state: S,
    /// The expected duties emitted during the transition
    pub expected_duties: Vec<D>,
    /// The expected signals emitted during the transition
    pub expected_signals: Vec<Sig>,
}

/// Test a single state transition with concrete values.
///
/// This helper function:
/// 1. Creates a state machine in the initial state
/// 2. Processes the event
/// 3. Asserts the transition succeeded
/// 4. Verifies the final state matches expectations
/// 5. Verifies duties and signals match expectations
///
/// Note: Your state machine type must provide a `state()` or similar method
/// to access the current state for verification.
pub fn test_transition<SM, S, E, D, Sig, Err, CreateFn, GetStateFn>(
    create_sm: CreateFn,
    get_state: GetStateFn,
    config: &SM::Config,
    transition: Transition<S, E, D, Sig>,
) where
    SM: StateMachine<Event = E, Duty = D, OutgoingSignal = Sig, Error = Err>,
    S: PartialEq + Debug,
    D: PartialEq + Debug,
    Sig: PartialEq + Debug + Into<Signal>,
    Err: Debug,
    CreateFn: Fn(S) -> SM,
    GetStateFn: Fn(&SM) -> &S,
{
    let mut sm = create_sm(transition.from_state);

    let result = sm.process_event(config, transition.event);

    assert!(
        result.is_ok(),
        "Expected successful transition, got error: {:?}",
        result.unwrap_err()
    );

    let output = result.unwrap();

    assert_eq!(
        get_state(&sm),
        &transition.expected_state,
        "State mismatch after transition"
    );

    assert_eq!(output.duties, transition.expected_duties, "Duties mismatch");

    assert_eq!(
        output.signals, transition.expected_signals,
        "Signals mismatch"
    );
}

/// Describes an invalid state-event pair that should produce an error.
#[derive(Debug)]
pub struct InvalidTransition<S, E, Err> {
    /// The initial state
    pub from_state: S,
    /// The event that should be rejected
    pub event: E,
    /// A function to verify the error type
    pub expected_error: fn(&Err) -> bool,
}

/// Test that an invalid transition produces the expected error.
pub fn test_invalid_transition<SM, S, E, D, Sig, Err, CreateFn>(
    create_sm: CreateFn,
    config: &SM::Config,
    invalid: InvalidTransition<S, E, Err>,
) where
    SM: StateMachine<Event = E, Duty = D, OutgoingSignal = Sig, Error = Err>,
    S: Debug,
    D: Debug,
    Sig: Into<Signal> + Debug,
    Err: Debug,
    CreateFn: Fn(S) -> SM,
{
    let mut sm = create_sm(invalid.from_state);

    let result = sm.process_event(config, invalid.event);

    assert!(result.is_err(), "Expected error, but transition succeeded");

    let err = result.unwrap_err();

    assert!(
        (invalid.expected_error)(&err),
        "Error type mismatch. Got: {:?}, Expected: {:?}",
        err,
        invalid.expected_error
    );
}

/// Event sequence tester for integration testing.
///
/// Allows you to run a sequence of concrete events through a state machine
/// and collect all outputs for verification.
#[derive(Debug)]
pub struct EventSequence<SM, S, GetStateFn>
where
    SM: StateMachine,
    GetStateFn: Fn(&SM) -> &S,
{
    sm: SM,
    get_state: GetStateFn,
    outputs: Vec<SMOutput<SM::Duty, SM::OutgoingSignal>>,
    errors: Vec<(usize, SM::Error)>, // Store index instead of event to avoid Clone requirement
}

impl<SM, S, GetStateFn> EventSequence<SM, S, GetStateFn>
where
    SM: StateMachine,
    GetStateFn: Fn(&SM) -> &S,
{
    /// Creates a new event sequence tester.
    pub const fn new(sm: SM, get_state: GetStateFn) -> Self {
        Self {
            sm,
            get_state,
            outputs: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Process an event and record the result.
    pub fn process(&mut self, config: &SM::Config, event: SM::Event) -> &mut Self {
        let event_idx = self.outputs.len() + self.errors.len();
        match self.sm.process_event(config, event) {
            Ok(output) => self.outputs.push(output),
            Err(e) => self.errors.push((event_idx, e)),
        }
        self
    }

    /// Get reference to the current state.
    pub fn state(&self) -> &S {
        (self.get_state)(&self.sm)
    }

    /// Assert that all events succeeded (no errors).
    pub fn assert_no_errors(&self) -> &Self
    where
        SM::Error: Debug,
    {
        assert!(
            self.errors.is_empty(),
            "Expected no errors, but got {} errors at indices: {:?}",
            self.errors.len(),
            self.errors.iter().map(|(idx, _)| idx).collect::<Vec<_>>()
        );
        self
    }

    /// Assert the final state matches expectation.
    pub fn assert_final_state(&self, expected: &S) -> &Self
    where
        S: PartialEq + Debug,
    {
        let cur_state = self.state();
        assert_eq!(
            self.state(),
            expected,
            "Final state mismatch, expected: {:?}, got: {:?}",
            expected,
            cur_state
        );

        self
    }

    /// Get all duties emitted during the sequence.
    pub fn all_duties(&self) -> Vec<&SM::Duty> {
        self.outputs.iter().flat_map(|o| &o.duties).collect()
    }

    /// Get all signals emitted during the sequence.
    pub fn all_signals(&self) -> Vec<&SM::OutgoingSignal> {
        self.outputs.iter().flat_map(|o| &o.signals).collect()
    }

    /// Get all the errors during processing.
    pub fn all_errors(&self) -> Vec<&SM::Error> {
        self.errors.iter().map(|(_, e)| e).collect()
    }

    /// Assert that specific duties were emitted (in any order).
    pub fn assert_duties_contain(&self, expected: &[SM::Duty]) -> &Self
    where
        SM::Duty: PartialEq + Debug,
    {
        let all_duties = self.all_duties();
        for duty in expected {
            assert!(
                all_duties.contains(&duty),
                "Expected duty {:?} not found. All duties: {:?}",
                duty,
                all_duties
            );
        }
        self
    }
}
