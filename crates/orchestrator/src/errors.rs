//! Error types for the orchestrator crate.

use strata_bridge_primitives::covenant::StakeKey;
use strata_bridge_sm::{operator_set::OperatorSetError, signals::Signal, state_machine::SMOutput};
use thiserror::Error;

use crate::{
    persister::PersistError,
    sm_registry::RegistryInsertError,
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// Error emitted when processing events for a state machine.
///
/// This type is reserved for fatal processing failures.
#[derive(Debug, Clone, Error)]
pub enum ProcessError {
    /// The state machine with the given id was not found in the registry.
    #[error("State machine with id {0} not found in the registry.")]
    SMNotFound(SMId),

    /// The event is invalid for the state machine, for example, a deposit event was sent to a
    /// graph state machine.
    #[error("Invalid invocation, params: ({0}, {1})")]
    InvalidInvocation(SMId, SMEvent),

    /// The state machine violated an invariant during event processing.
    #[error("Failed to process event {1} for state machine with id {0} in state: {2}: {3}")]
    InvariantViolation(Box<SMId>, SMEvent, String, String),

    /// A duplicate or invalid registry insertion was attempted.
    #[error("Registry insertion error: {0}")]
    RegistryInsert(#[from] RegistryInsertError),

    /// The membership transition failed and must not be skipped to finalize the block.
    #[error("operator membership transition failed: {0}")]
    OperatorSet(#[from] OperatorSetError),
}

/// Fatal error from the pipeline main loop.
#[derive(Debug, Error)]
pub enum PipelineError {
    /// A fatal error occurred while processing an event through a state machine.
    #[error("process error: {0}")]
    Process(#[from] ProcessError),

    /// A fatal error occurred while persisting state to disk.
    #[error("persist error: {0}")]
    Persist(#[from] PersistError),

    /// Stake creation must be applied before a membership signal can be consumed.
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-4040>
    // Handle initialization synchronously in the applicator.
    #[error("stake initialization is not integrated for {0}")]
    StakeInitializationRequired(StakeKey),
}

/// Unified output from processing an event through any state machine.
pub type ProcessOutput = SMOutput<UnifiedDuty, Signal>;
