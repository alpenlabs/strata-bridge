# Testing Framework for State Machines

This module provides a comprehensive testing framework for state machines implementing the `StateMachine` trait. The framework separates value-based transition testing from property-based testing, promotes DRY principles, and provides organized test structure.

## Table of Contents

- [Testing Module Organization](#testing-module-organization)
- [Test Helper Organization](#test-helper-organization)
- [Value-Based Transition Testing](#value-based-transition-testing)
- [Property-Based Testing](#property-based-testing)
- [Creating Tests for a New State Machine](#creating-tests-for-a-new-state-machine)
- [Example: DepositSM](#example-depositsm)
- [Best Practices](#best-practices)

## Testing Module Organization

The testing framework is organized into three modules:

### `fixtures` - Universal Test Fixtures

Provides common test data structures (blocks, transactions, etc.) that can be used by any state machine.

### `transition` - Value-Based Transition Testing

Helpers for testing state machines with specific, concrete values:
- `Transition` - Declarative transition specification
- `InvalidTransition` - Error case specification
- `EventSequence` - Integration testing with sequences of events
- `test_transition()` - Test a single valid transition
- `test_invalid_transition()` - Test error cases

### `proptest` - Property-Based Testing

Macros for testing invariant properties over arbitrary inputs:
- `prop_deterministic!` - Verify deterministic behavior
- `prop_no_silent_acceptance!` - Verify state changes or errors
- `prop_terminal_states_reject!` - Verify terminal state behavior

## Test Helper Organization

Test helpers are organized into **three levels**:

### Level 1: Universal Helpers (`src/testing/fixtures.rs`)

Helpers that can be used by **any state machine** in the crate. These provide common test data structures like blocks and transactions.

**Example:**
```rust
use crate::testing::fixtures::*;

let block = test_block_with_height(100);
let tx = test_payout_tx(OutPoint::default());
```

### Level 2: State Machine-Specific Helpers (`src/<module>/testing.rs`)

Helpers specific to a particular state machine but **reusable across multiple state transition functions (STFs)**. This includes:

- Test constants
- Configuration builders
- `Arbitrary` trait implementations
- State machine factory functions

**Example:** `src/deposit/testing.rs`
```rust
use crate::deposit::testing::*;

let sm = create_sm(DepositState::Created { ... });
let cfg = test_cfg();
```

### Level 3: STF-Specific Tests (`src/<module>/state.rs`)

The actual test implementations for specific state transition functions. These should import from Level 1 and Level 2.

**Example:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deposit::testing::*,
        testing::{fixtures::*, *},
    };

    #[test]
    fn test_my_transition() {
        // Test implementation
    }
}
```

## Value-Based Transition Testing

Value-based testing uses specific, concrete inputs to test state transitions. Import from `crate::testing::transition::*`.

### `Transition` - Testing Valid Transitions

Use the `Transition` struct with the `test_transition` helper to declaratively test valid state transitions:

```rust
use crate::testing::transition::*;

#[test]
fn test_valid_transition() {
    test_transition(
        create_sm,
        get_state,
        Transition {
            from_state: MyState::Initial,
            event: MyEvent::Start,
            expected_state: MyState::Running,
            expected_duties: vec![MyDuty::Initialize],
            expected_signals: vec![MySignal::Started],
        },
    );
}
```

**Fields:**
- `from_state`: The initial state before the transition
- `event`: The event that triggers the transition
- `expected_state`: The expected state after the transition
- `expected_duties`: The expected duties emitted during the transition
- `expected_signals`: The expected signals emitted during the transition

### `InvalidTransition` - Testing Error Cases

Use the `InvalidTransition` struct to test that invalid state-event pairs produce the expected errors:

```rust
#[test]
fn test_invalid_transition() {
    test_invalid_transition(
        create_sm,
        InvalidTransition {
            from_state: MyState::Terminal,
            event: MyEvent::Start,
            expected_error: |e| matches!(e, MyError::InvalidEvent { .. }),
        },
    );
}
```

**Fields:**
- `from_state`: The initial state
- `event`: The event that should be rejected
- `expected_error`: A function to verify the error type

### `EventSequence` - Integration Testing

Use `EventSequence` to test sequences of events and collect outputs:

```rust
#[test]
fn test_event_sequence() {
    let sm = create_sm(MyState::Initial);
    let mut seq = EventSequence::new(sm, get_state);

    seq.process(MyEvent::Start)
       .process(MyEvent::Continue)
       .process(MyEvent::Finish);

    seq.assert_no_errors()
       .assert_final_state(&MyState::Complete);

    // Check emitted duties/signals
    let duties = seq.all_duties();
    let signals = seq.all_signals();
}
```

**Methods:**
- `process(event)`: Process an event and record the result
- `state()`: Get reference to the current state
- `assert_no_errors()`: Assert that all events succeeded
- `assert_final_state(expected)`: Assert the final state matches expectation
- `all_duties()`: Get all duties emitted during the sequence
- `all_signals()`: Get all signals emitted during the sequence
- `assert_duties_contain(expected)`: Assert that specific duties were emitted

## Property-Based Testing

Property-based testing verifies invariants over arbitrary inputs generated by proptest. The macros are defined in `crate::testing::proptest` but exported at the crate root for convenience.

### `prop_deterministic!` - Determinism Property

Tests that the state machine is deterministic: given the same initial state and event, it always produces the same result.

```rust
prop_deterministic!(
    MySM,
    create_sm,
    get_state,
    any::<MyState>(),
    any::<MyEvent>()
);
```

### `prop_no_silent_acceptance!` - No Silent Acceptance Property

Tests that events must either transition state or produce an error. State machines should never silently accept events without changing state or emitting duties/signals.

```rust
prop_no_silent_acceptance!(
    MySM,
    create_sm,
    get_state,
    any::<MyState>(),
    any::<MyEvent>()
);
```

### `prop_terminal_states_reject!` - Terminal States Property

Tests that terminal states reject all events with errors.

```rust
prop_terminal_states_reject!(
    MySM,
    create_sm,
    arb_terminal_state(),
    any::<MyEvent>(),
);
```

## Creating Tests for a New State Machine

### Step 1: Create State Machine-Specific Testing Module

Create `src/<your_module>/testing.rs`:

```rust
//! Testing utilities specific to <YourSM> State Machine.

use proptest::prelude::*;
use super::state::{YourCfg, YourSM, YourState};
use super::events::YourEvent;

// ===== Test Constants =====

/// Description of constant
pub const TEST_CONSTANT: u64 = 100;

// ===== Configuration Helpers =====

/// Creates a test configuration for YourSM.
pub fn test_cfg() -> YourCfg {
    YourCfg {
        // ... configuration fields
    }
}

// ===== State Machine Helpers =====

/// Creates a YourSM from a given state.
pub fn create_sm(state: YourState) -> YourSM {
    YourSM {
        cfg: test_cfg(),
        state,
    }
}

/// Gets the state from a YourSM.
pub const fn get_state(sm: &YourSM) -> &YourState {
    sm.state()
}

// ===== Arbitrary Implementations =====

impl Arbitrary for YourState {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            // Generate arbitrary states
            Just(YourState::State1),
            Just(YourState::State2),
            // ...
        ]
        .boxed()
    }
}

impl Arbitrary for YourEvent {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            // Generate arbitrary events
            Just(YourEvent::Event1),
            Just(YourEvent::Event2),
            // ...
        ]
        .boxed()
    }
}

/// Strategy for generating only terminal states.
pub fn arb_terminal_state() -> impl Strategy<Value = YourState> {
    prop_oneof![
        Just(YourState::Terminal1),
        Just(YourState::Terminal2),
    ]
}
```

### Step 2: Declare the Testing Module

In `src/<your_module>/mod.rs`:

```rust
#[cfg(any(test, feature = "testing"))]
pub mod testing;
```

### Step 3: Make Necessary Fields Visible

If your state machine or configuration has private fields that tests need to access, make them `pub(crate)`:

```rust
pub struct YourSM {
    pub(crate) cfg: YourCfg,
    pub(crate) state: YourState,
}

pub struct YourCfg {
    pub(crate) field1: Type1,
    pub(crate) field2: Type2,
}
```

### Step 4: Write Tests

In `src/<your_module>/state.rs`:

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use super::*;
    use crate::{
        your_module::testing::*,
        prop_deterministic, prop_no_silent_acceptance,
        testing::{fixtures::*, transition::*},
    };

    // ===== Unit Tests =====

    #[test]
    fn test_specific_transition() {
        test_transition(
            create_sm,
            get_state,
            Transition {
                from_state: YourState::Initial,
                event: YourEvent::Start,
                expected_state: YourState::Running,
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    // ===== Property-Based Tests =====

    prop_deterministic!(
        YourSM,
        create_sm,
        get_state,
        any::<YourState>(),
        any::<YourEvent>()
    );

    prop_no_silent_acceptance!(
        YourSM,
        create_sm,
        get_state,
        any::<YourState>(),
        any::<YourEvent>()
    );

    // ===== Integration Tests =====

    #[test]
    fn test_full_lifecycle() {
        let sm = create_sm(YourState::Initial);
        let mut seq = EventSequence::new(sm, get_state);

        seq.process(YourEvent::Event1)
           .process(YourEvent::Event2)
           .process(YourEvent::Event3);

        seq.assert_no_errors()
           .assert_final_state(&YourState::Complete);
    }
}
```

## Example: DepositSM

The `DepositSM` provides a complete example of the testing framework in action:

### Universal Fixtures (`src/testing/fixtures.rs`)

```rust
pub fn test_block_with_height(height: u64) -> Block { /* ... */ }
pub fn test_tx(previous_output: OutPoint, witness_elements: &[Vec<u8>]) -> Transaction { /* ... */ }
pub fn test_takeback_tx(outpoint: OutPoint) -> Transaction { /* ... */ }
pub fn test_payout_tx(outpoint: OutPoint) -> Transaction { /* ... */ }
```

### DepositSM-Specific Helpers (`src/deposit/testing.rs`)

```rust
pub const INITIAL_BLOCK_HEIGHT: u64 = 100;
pub const LATER_BLOCK_HEIGHT: u64 = 150;
pub const TEST_ASSIGNEE: OperatorIdx = 0;

pub fn test_cfg() -> DepositCfg { /* ... */ }
pub fn test_operator_table() -> OperatorTable { /* ... */ }
pub fn create_sm(state: DepositState) -> DepositSM { /* ... */ }
pub const fn get_state(sm: &DepositSM) -> &DepositState { /* ... */ }

impl Arbitrary for DepositState { /* ... */ }
impl Arbitrary for DepositEvent { /* ... */ }
pub fn arb_terminal_state() -> impl Strategy<Value = DepositState> { /* ... */ }
```

### DepositSM Tests (`src/deposit/state.rs`)

```rust
#[test]
fn test_drt_takeback_from_created() {
    let outpoint = OutPoint::default();
    let state = DepositState::Created {
        deposit_request_outpoint: outpoint,
        block_height: INITIAL_BLOCK_HEIGHT,
    };

    let tx = test_takeback_tx(outpoint);

    test_transition(
        create_sm,
        get_state,
        Transition {
            from_state: state,
            event: DepositEvent::UserTakeBack { tx },
            expected_state: DepositState::Aborted,
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}
```

## Best Practices

### 1. DRY Principle

- **Extract constants** for magic numbers (block heights, timeouts, etc.)
- **Create helper functions** for commonly constructed objects (transactions, blocks, etc.)
- **Reuse fixtures** from the universal fixtures module when possible

### 2. Implement Arbitrary Trait

Implementing the `Arbitrary` trait for your states and events enables:
- Property-based testing
- Automatic generation of test cases
- Discovery of edge cases you might not have considered
- Principled approach to testing

### 3. Test Organization

Organize your tests into these categories:

- **Unit tests (value-based)**: Test individual state transition functions with concrete values
- **Integration tests (value-based)**: Test sequences of events using `EventSequence`
- **Property tests**: Test invariants over arbitrary inputs using proptest macros
- **Error tests (value-based)**: Test error cases with specific inputs

Keep value-based tests (concrete inputs) separate from property-based tests (arbitrary inputs) for clarity.

### 4. Constants Over Magic Numbers

```rust
// Bad
let block = test_block_with_height(100);
let later_block = test_block_with_height(150);

// Good
const INITIAL_BLOCK_HEIGHT: u64 = 100;
const LATER_BLOCK_HEIGHT: u64 = 150;

let block = test_block_with_height(INITIAL_BLOCK_HEIGHT);
let later_block = test_block_with_height(LATER_BLOCK_HEIGHT);
```

## Contributing

When adding new universal test fixtures, add them to `src/testing/fixtures.rs`. Document their purpose and provide examples of how to use them.

When implementing tests for a new state machine, follow the three-level organization structure to keep tests maintainable and reusable.
