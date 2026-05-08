//! Error types for the bridge-exec executors.

use bdk_wallet::error::CreateTxError;
use bitcoin::{FeeRate, OutPoint, Txid};
use foundationdb::FdbBindingError;
use strata_bridge_db::fdb::errors::LayerError;
use terrors::OneOf;
use thiserror::Error;

/// Errors that can occur during executor operations.
#[derive(Debug, Error)]
pub enum ExecutorError {
    /// Error from secret service requests.
    #[error("secret service error: {0:?}")]
    SecretServiceErr(#[from] secret_service_proto::v2::traits::ClientError),

    /// Error from tx driver while submitting/tracking transaction.
    #[error("transaction driver error: {0:?}")]
    TxDriverErr(#[from] btc_tracker::tx_driver::DriveErr),

    /// Our pubkey was not found in the MuSig2 params.
    #[error("our pubkey not in params")]
    OurPubKeyNotInParams,

    /// The partial signature we generated failed self-verification.
    #[error("partial signature self-verification failed")]
    SelfVerifyFailed,

    /// Missing required configuration.
    #[error("missing configuration: {0}")]
    MissingConfig(String),

    /// Wallet-related error.
    #[error("wallet error: {0}")]
    WalletErr(String),

    /// Error related to creation of [`Psbt`](bitcoin::psbt::Psbt).
    #[error("psbt error: {0}")]
    PsbtErr(#[from] CreateTxError),

    /// Failed to aggregate partial signatures into final Schnorr signature.
    #[error("signature aggregation failed: {0}")]
    SignatureAggregationFailed(String),

    /// Error from Bitcoin Core RPC.
    #[error("bitcoin rpc error: {0:?}")]
    BitcoinRpcErr(#[from] bitcoind_async_client::error::ClientError),

    /// The claim transaction already exists on chain.
    #[error("claim transaction {0} already exists on chain")]
    ClaimTxAlreadyOnChain(Txid),

    /// The operator's stake outpoint has already been spent on chain — the slash path that backs
    /// this graph is dead, so partial signatures must not be published.
    #[error("stake outpoint {0} already spent on chain")]
    StakeOutPointAlreadySpent(OutPoint),

    /// Error interacting with the database.
    #[error("database error: {0:?}")]
    DatabaseErr(OneOf<(FdbBindingError, LayerError)>),

    /// Error interacting with the mosaic service.
    #[error("mosaic error: {0}")]
    MosaicErr(String),

    /// Error interacting with the ASM RPC.
    #[error("asm rpc error: {0}")]
    AsmRpcErr(String),

    /// Error generating a ZK proof.
    #[error("proof generation error: {0}")]
    ProofErr(#[from] strata_bridge_proof_common::ProofError),

    /// A transaction or its template violates a protocol invariant
    #[error("invalid transaction structure: {0}")]
    InvalidTxStructure(String),

    /// The fee rate estimated for a transaction exceeds the maximum allowed by the configuration.
    #[error("fee rate {fee_rate} exceeds maximum of {max}")]
    FeeRateTooHigh {
        /// The fee rate that was estimated for the transaction.
        fee_rate: FeeRate,
        /// The maximum fee rate allowed by the configuration.
        max: FeeRate,
    },
}

impl From<OneOf<(FdbBindingError, LayerError)>> for ExecutorError {
    fn from(err: OneOf<(FdbBindingError, LayerError)>) -> Self {
        ExecutorError::DatabaseErr(err)
    }
}
