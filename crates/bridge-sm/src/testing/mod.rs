#![expect(unreachable_pub)] // remove once the testing macros/functions are used
#![expect(unused_imports)] // remove once the testing macros/functions are used
#![expect(dead_code)] // remove once the testing macros/functions are used
//! Generic testing utilities for state machines.
//!
//! This module provides reusable testing infrastructure for all state machines
//! implementing the `StateMachine` trait.
//!
//! ## Organization
//!
//! - [`fixtures`] - Universal test fixtures (blocks, transactions, etc.)
//! - [`transition`] - Value-based transition testing helpers
//! - [`proptest`] - Property-based testing macros
//!
//! ## Value-Based Testing
//!
//! Use the helpers in [`transition`] to test state machines with specific, concrete values:
//!
//! ```rust,ignore
//! use crate::testing::transition::*;
//!
//! test_transition(
//!     create_sm,
//!     get_state,
//!     Transition {
//!         from_state: MyState::Initial,
//!         event: MyEvent::Start,
//!         expected_state: MyState::Running,
//!         expected_duties: vec![],
//!         expected_signals: vec![],
//!     },
//! );
//! ```
//!
//! ## Property-Based Testing
//!
//! Use the macros in [`proptest`] to test invariant properties over arbitrary inputs:
//!
//! ```rust,ignore
//! use crate::{prop_deterministic, prop_no_silent_acceptance};
//! use proptest::prelude::*;
//!
//! prop_deterministic!(
//!     MySM,
//!     create_sm,
//!     get_state,
//!     any::<MyState>(),
//!     any::<MyEvent>()
//! );
//! ```

pub mod fixtures;
pub mod proptest;
pub mod signer;
pub mod transition;

// Re-export commonly used items for convenience
pub use transition::{
    EventSequence, InvalidTransition, Transition, test_invalid_transition, test_transition,
};
