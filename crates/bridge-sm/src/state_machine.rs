//! Generic state machine infrastructure for the bridge.
//!
//! This module provides the core abstractions for all state machines in the bridge system,
//! including the generic output type and the trait that all state machines implement.

use crate::{cross_sm_context::CrossSmContext, signals::Signal};

/// Whether a state transition mutated the state machine's persistent state.
///
/// Every [`SMOutput`] constructor defaults to [`Mutated`](Self::Mutated); a transition that
/// leaves state unchanged opts in to [`Unchanged`](Self::Unchanged) via
/// [`SMOutput::mark_unchanged`]. The default fails safe: a handler that omits the marker is
/// treated as mutating, so a state change is never silently dropped.
// TODO: <https://alpenlabs.atlassian.net/browse/STR-3493>
// Remove this enum once only true transitions exist in the `process_event` STF, and the rest (nags,
// retries) are moved to separate handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum StateMutation {
    /// The transition mutated state and must be persisted.
    #[default]
    Mutated,
    /// The transition left the state machine unchanged.
    Unchanged,
}

/// Generic output from any state machine after processing an event.
///
/// This struct is used by all state machines in the bridge system. It contains:
/// - `duties`: Actions that need to be executed externally
/// - `signals`: Messages to be sent to other state machines
/// - `state_mutation`: Whether the transition changed persistent state
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
    /// Whether the transition that produced this output mutated state machine state.
    pub(crate) state_mutation: StateMutation,
}

impl<D, S> Default for SMOutput<D, S>
where
    S: Into<Signal>,
{
    fn default() -> Self {
        Self {
            duties: Vec::new(),
            signals: Vec::new(),
            state_mutation: StateMutation::Mutated,
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
            state_mutation: StateMutation::Mutated,
        }
    }

    /// Creates an output with only signals.
    pub const fn with_signals(signals: Vec<S>) -> Self {
        Self {
            duties: Vec::new(),
            signals,
            state_mutation: StateMutation::Mutated,
        }
    }

    /// Creates an output with both duties and signals.
    pub const fn with_duties_and_signals(duties: Vec<D>, signals: Vec<S>) -> Self {
        Self {
            duties,
            signals,
            state_mutation: StateMutation::Mutated,
        }
    }

    /// Marks this output as the result of a transition that left state unchanged.
    pub const fn mark_unchanged(mut self) -> Self {
        self.state_mutation = StateMutation::Unchanged;
        self
    }

    /// Returns whether this output is the result of a transition that mutated state.
    pub const fn did_mutate(&self) -> bool {
        matches!(self.state_mutation, StateMutation::Mutated)
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
///     type Config = Arc<DepositSMCfg>;
///     type OutgoingSignal = DepositSignal;  // Can only emit DepositSignal variants
///     type Event = DepositEvent;
///     type Error = DSMError;
///
///     fn process_event(&mut self, cfg: Self::Config, event: Self::Event)
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

    /// Static configuration required by this state machine.
    type Config;

    /// Processes an event and returns the output (duties and signals) or an error.
    ///
    /// This is the main entry point for advancing the state machine. The implementation
    /// should perform the appropriate state transition based on the current state and
    /// the incoming event, then return any duties to be executed and signals to be sent
    /// to other state machines.
    fn process_event(
        &mut self,
        cfg: Self::Config,
        event: Self::Event,
    ) -> Result<SMOutput<Self::Duty, Self::OutgoingSignal>, Self::Error>;

    /// Runs after a successful state transition and derives append-only duties from the settled
    /// state plus destination-scoped cross-SM context.
    ///
    /// This hook intentionally receives `&self` and returns a fresh duty list: it is not part of
    /// the STF, must not mutate state, and must not emit signals.
    fn run_post_stf_hook(
        &self,
        _cfg: &Self::Config,
        _cross_sm_context: &CrossSmContext,
    ) -> Vec<Self::Duty> {
        Vec::new()
    }
}
