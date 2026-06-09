use std::error::Error;

use strata_bridge_primitives::types::{GameIndex, OperatorIdx};

use crate::types::Role;

/// Errors arising from mosaic operations.
#[derive(Debug, thiserror::Error)]
pub enum MosaicError {
    /// The mosaic setup was explicitly aborted.
    #[error("mosaic setup aborted: {0}")]
    Aborted(String),
    /// The mosaic setup is missing.
    #[error("mosaic setup missing: {0}|{1}")]
    SetupMissing(OperatorIdx, Role),
    /// The deposit was aborted before completion.
    #[error("game {0} aborted")]
    DepositAborted(GameIndex),
    /// The deposit was not seen within timeout.
    #[error("deposit missing: {0}|{1}|{2}")]
    DepositMissing(OperatorIdx, Role, GameIndex),
    /// The deposit has already been withdrawn.
    #[error("game {0} already withdrawn")]
    DepositWithdrawn(GameIndex),
    /// The deposit is in an unexpected state.
    #[error("unexpected deposit state: {0}")]
    UnexpectedDepositState(String),
    /// A deposit contest arrived for a different deposit than expected.
    #[error("unexpected deposit contest: expected {expected}, got {actual}")]
    UnexpectedDepositContest {
        /// Expected deposit id
        expected: String,
        /// Actual deposit id
        actual: String,
    },
    /// The fault secret is missing when it should have been available.
    #[error("fault secret unexpectedly missing for game {0}")]
    UnexpectedMissingFinalSecret(GameIndex),
    /// An RPC communication error with the mosaic service.
    #[error("mosaic RPC error")]
    RpcError(#[source] Box<dyn Error + Send + Sync + 'static>),
    /// Operator could not be resolved.
    #[error("unknown operator: {0}")]
    UnknownOperator(OperatorIdx),
}

impl MosaicError {
    /// Wraps an arbitrary error as an [`MosaicError::RpcError`].
    pub fn rpc_error(error: impl Error + Send + Sync + 'static) -> Self {
        Self::RpcError(Box::new(error))
    }
}

/// Errors specific to the mosaic setup phase.
#[derive(Debug, thiserror::Error)]
pub enum MosaicSetupError {
    /// The setup was explicitly aborted.
    #[error("mosaic setup aborted: {0}; manual intervention required")]
    Aborted(String),

    /// The mosaic setup is missing.
    #[error("mosaic setup missing for operator {0} role {1}")]
    SetupMissing(OperatorIdx, Role),

    /// An RPC communication error during setup.
    #[error("mosaic setup RPC error: {0}")]
    RpcError(#[source] Box<dyn Error + Send + Sync + 'static>),
}

impl MosaicSetupError {
    /// Wraps an arbitrary error as a [`MosaicSetupError::RpcError`].
    pub fn rpc_error(error: impl Error + Send + Sync + 'static) -> Self {
        Self::RpcError(Box::new(error))
    }
}
