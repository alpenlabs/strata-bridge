//! Errors of the transaction driver.

use bitcoin::Txid;
use bitcoind_async_client::error::ClientError;
use thiserror::Error;

/// Error type for the TxDriver.
#[derive(Debug, Clone, Error)]
pub enum DriveErr {
    /// Indicates that the TxDriver has been dropped and no more events should be expected.
    #[error("tx driver has been aborted, no more events should be expected")]
    DriverAborted,

    /// Indicates that the transaction could not be published.
    #[error("could not publish transaction: {0}")]
    PublishFailed(ClientError),

    /// Indicates that the transaction was evicted from the mempool and could not be rebroadcast.
    #[error("transaction {txid} was evicted from the mempool and rebroadcast failed: {source}")]
    Evicted {
        /// The id of the evicted transaction.
        txid: Txid,

        /// The error returned by the rebroadcast attempt.
        source: ClientError,
    },

    /// The transaction reached burial before the caller's condition was true. The driver
    /// stops tracking a transaction at burial, so the condition can never become true after
    /// this point.
    #[error("transaction was buried before the wait condition was met")]
    ConditionUnmet,
}
