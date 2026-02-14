//! Error types for the bridge-exec executors.

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

    /// Failed to aggregate partial signatures into final Schnorr signature.
    #[error("signature aggregation failed: {0}")]
    SignatureAggregationFailed(String),

    /// Error from Bitcoin Core RPC.
    #[error("bitcoin rpc error: {0:?}")]
    BitcoinRpcErr(#[from] bitcoind_async_client::error::ClientError),
}
