//! Generic state machine infrastructure for the bridge.
//!
//! This module provides the core abstractions for all state machines in the bridge system,
//! including the generic output type and the trait that all state machines implement.

use crate::signals::Signal;

/// Generic output from any state machine after processing an event.
///
/// This struct is used by all state machines in the bridge system. It contains:
/// - `duties`: Actions that need to be executed externally
/// - `signals`: Messages to be sent to other state machines
///
/// The type parameters ensure that each state machine can only emit duties and signals
/// that are appropriate for that state machine.
///
/// # Type Parameters
///
/// - `D`: The duty type specific to this state machine
/// - `S`: The signal type specific to this state machine (must be convertible to [`Signal`])
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SMOutput<D, S: Into<Signal>> {
    /// The duties that need to be performed by external executors.
    pub duties: Vec<D>,
    /// The signals that need to be sent to other state machines.
    pub signals: Vec<S>,
}

impl<D, S> Default for SMOutput<D, S>
where
    S: Into<Signal>,
{
    fn default() -> Self {
        Self {
            duties: Vec::new(),
            signals: Vec::new(),
        }
    }
}

impl<D, S> SMOutput<D, S>
where
    S: Into<Signal>,
{
    /// Creates a new empty output.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an output with only duties.
    pub const fn with_duties(duties: Vec<D>) -> Self {
        Self {
            duties,
            signals: Vec::new(),
        }
    }

    /// Creates an output with only signals.
    pub const fn with_signals(signals: Vec<S>) -> Self {
        Self {
            duties: Vec::new(),
            signals,
        }
    }

    /// Creates an output with both duties and signals.
    pub const fn with_duties_and_signals(duties: Vec<D>, signals: Vec<S>) -> Self {
        Self { duties, signals }
    }
}

/// Trait for all state machines in the bridge system.
///
/// This trait provides a uniform interface for processing events and emitting outputs.
/// Each state machine implementation specifies its own duty type, signal type, and event type
/// through associated types.
///
/// # Type Safety
///
/// The `OutgoingSignal` associated type is constrained to be convertible to [`Signal`],
/// ensuring that all signals can be unified when routing between state machines.
/// However, each state machine can only emit signals of its specific `OutgoingSignal` type,
/// preventing it from emitting signals it shouldn't be able to produce.
///
/// # Example
///
/// ```ignore
/// impl StateMachine for DepositSM {
///     type Duty = DepositDuty;
///     type OutgoingSignal = DepositSignal;  // Can only emit DepositSignal variants
///     type Event = DepositEvent;
///     type Error = DSMError;
///
///     fn process_event(&mut self, event: Self::Event)
///         -> Result<SMOutput<Self::Duty, Self::OutgoingSignal>, Self::Error>
///     {
///         // Implementation
///     }
/// }
/// ```
pub trait StateMachine {
    /// The type of duties this state machine can emit.
    type Duty;

    /// The type of signals this state machine can emit.
    ///
    /// Must be convertible to the unified [`Signal`] type for routing.
    type OutgoingSignal: Into<Signal>;

    /// The type of events this state machine can process.
    type Event;

    /// The error type returned when event processing fails.
    type Error;

    /// Processes an event and returns the output (duties and signals) or an error.
    ///
    /// This is the main entry point for advancing the state machine. The implementation
    /// should perform the appropriate state transition based on the current state and
    /// the incoming event, then return any duties to be executed and signals to be sent
    /// to other state machines.
    fn process_event(
        &mut self,
        event: Self::Event,
    ) -> Result<SMOutput<Self::Duty, Self::OutgoingSignal>, Self::Error>;
}
