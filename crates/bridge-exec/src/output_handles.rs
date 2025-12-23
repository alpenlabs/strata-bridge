//! The handles for external services that need to be accessed by the executors.

use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::tx_driver::TxDriver;
use operator_wallet::OperatorWallet;
use secret_service_client::SecretServiceClient;
use strata_bridge_p2p_service::MessageHandler;
use tokio::sync::RwLock;

/// The handles for external services that need to be accessed by the executors.
///
/// If this needs to be shared across multiple execuors, it should be wrapped in an
/// [`Arc`](std::sync::Arc).
#[derive(Debug)]
pub struct OutputHandles {
    /// Handle for accessing operator funds.
    pub wallet: RwLock<OperatorWallet>,

    /// Handle for broadcasting P2P messages.
    pub msg_handler: MessageHandler,

    /// Handle for accessing the Bitcoin client RPC.
    pub bitcoind_rpc_client: BitcoinClient,

    /// Handle for accessing the secret service.
    pub s2_client: SecretServiceClient,

    /// Handle for submitting Bitcoin transactions in a stateful manner.
    pub tx_driver: TxDriver,
}
