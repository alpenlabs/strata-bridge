//! Error types for the duty tracker.

use bdk_wallet::error::CreateTxError;
use bitcoin_bosd::DescriptorError;
use bitcoind_async_client::error::ClientError;
use btc_tracker::tx_driver::DriveErr;
use p2p_types::P2POperatorPubKey;
use p2p_wire::p2p::v1::{GetMessageRequest, UnsignedGossipsubMsg};
use strata_bridge_db::errors::DbError;
use strata_bridge_tx_graph::errors::TxGraphError;
use thiserror::Error;

use crate::{contract_persister::ContractPersistErr, contract_state_machine::TransitionErr};

/// Unified error type for everything that can happen in the ContractManager.
#[derive(Debug, Error)]
pub enum ContractManagerErr {
    /// Errors related to writing contract state to disk.
    #[error("failed to commit contract state to disk: {0}")]
    ContractPersistErr(#[from] ContractPersistErr),

    /// Errors related to state machines being unable to process ContractEvents
    #[error("contract state machine received an invalid event: {0}")]
    TransitionErr(#[from] TransitionErr),

    /// Errors related to events updating operators' stake chains.
    #[error("stake chain state machine received an invalid event: {0}")]
    StakeChainErr(#[from] StakeChainErr),

    /// Errors related to PegOutGraph generation.
    #[error("peg out graph generation failed: {0}")]
    TxGraphError(#[from] TxGraphError),

    /// Errors related to receiving P2P messages at protocol-invalid times.
    #[error("invalid p2p message: {0:?}")]
    InvalidP2PMessage(Box<UnsignedGossipsubMsg>),

    /// Errors related to receiving P2P message requests that are invalid.
    #[error("invalid p2p request: {0:?}")]
    InvalidP2PRequest(Box<GetMessageRequest>),

    /// Errors related to calling Bitcoin Core's RPC interface.
    #[error("bitcoin core rpc call failed with: {0}")]
    BitcoinCoreRPCErr(#[from] ClientError),

    /// Errors from failed secret service requests
    #[error("secret service request failed with {0:?}")]
    SecretServiceErr(#[from] secret_service_proto::v2::traits::ClientError),

    /// Errors from the bridge db
    #[error("database error: {0:?}")]
    DbErr(#[from] DbError),

    /// Error during transaction creation
    #[error("error while creating transaction: {0:?}")]
    CreateTxErr(#[from] CreateTxError),

    /// General catch-all for errors.
    #[error("fatal error: {0}")]
    FatalErr(String),

    /// Error from the tx driver while submitting/tracking transaction on chain.
    #[error("failed to submit or track transaction: {0:?}")]
    TxDriverErr(#[from] DriveErr),

    /// Invalid operator descriptor.
    #[error("invalid operator descriptor: {0}")]
    InvalidOperatorDescriptor(#[from] DescriptorError),
}

impl From<String> for ContractManagerErr {
    fn from(msg: String) -> Self {
        ContractManagerErr::FatalErr(msg)
    }
}

impl From<&str> for ContractManagerErr {
    fn from(msg: &str) -> Self {
        ContractManagerErr::FatalErr(msg.to_string())
    }
}

/// Error type for problems arising in maintaining or querying stake chain data.
#[derive(Debug, Error)]
pub enum StakeChainErr {
    /// Error indicating that the operator p2p key not found in the operator table.
    #[error("operator p2p key invalid: {0}")]
    OperatorP2PKeyNotFound(P2POperatorPubKey),

    /// Error indicating that the state machine is missing some operator keys.
    #[error("stake inputs missing for operators: {0:?}")]
    IncompleteState(Vec<P2POperatorPubKey>),

    /// Error indicating an inconsistent state in the
    /// [`StakeChainSM`](crate::stake_chain_state_machine::StakeChainSM) such that an expected
    /// stake txid is not present.
    #[error("stake txid missing for operator: {0}, index: {1}")]
    MissingStakeTxid(P2POperatorPubKey, u32),

    /// Error indicating that some stake chain data is missing.
    #[error("stake chain inputs incomplete for operator: {0}, index: {1}")]
    IncompleteStakeChainInput(P2POperatorPubKey, u32),

    /// Error indicating that the pre stake data for the operator does not exist in the database.
    #[error("stake setup data not found for operator: {0}")]
    StakeSetupDataNotFound(P2POperatorPubKey),

    /// Error indicating that the stake transaction for the operator does not exist for the given
    /// deposit index in the database.
    #[error("stake tx not found for operator: {0} and deposit: {1}")]
    StakeTxNotFound(P2POperatorPubKey, u32),

    /// Error indicating a problem with the operator descriptor.
    #[error("descriptor error: {0}")]
    InvalidOperatorDescriptor(#[from] DescriptorError),

    /// Error indicating unexpected behavior in the stake chain state machine.
    #[error("unexpected problem with stake chain state machine: {0}")]
    Unexpected(String),
}

/// Error type for shutdown operations.
#[derive(Debug, Error)]
pub enum ShutdownErr {
    /// Error during contract state persistence.
    #[error("failed to persist contract state: {0}")]
    ContractPersistErr(#[from] ContractPersistErr),

    /// Error during stake chain state persistence.
    #[error("failed to persist stake chain state: {0}")]
    StakeChainPersistErr(#[from] DbError),

    /// Timeout during shutdown operations
    #[error("timeout during shutdown operation: {0}")]
    ShutdownTimeout(String),

    /// Error indicatiing unexpected behavior during shutdown.
    #[error("unexpected problem with the shutdown operation: {0}")]
    Unexpected(String),
}
