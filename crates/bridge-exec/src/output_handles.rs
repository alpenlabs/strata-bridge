//! The handles for external services that need to be accessed by the executors.

use std::sync::Arc;

use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::tx_driver::TxDriver;
use operator_wallet::OperatorWallet;
use secret_service_client::SecretServiceClient;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_p2p_service::MessageHandler;
use tokio::sync::RwLock;

/// The handles for external services that need to be accessed by the executors.
///
/// If this needs to be shared across multiple executors, it should be wrapped in an
/// [`Arc`].
#[derive(Debug)]
pub struct OutputHandles {
    /// Handle for accessing operator funds.
    pub wallet: RwLock<OperatorWallet>,

    /// Handle for accessing the database.
    // TODO: <https://atlassian.alpenlabs.net/browse/STR-2670>
    // Make this generic over `BridgeDb` instead of tying it to `FdbClient`.
    pub db: Arc<FdbClient>,

    /// Handle for broadcasting P2P messages
    pub msg_handler: RwLock<MessageHandler>,

    /// Handle for accessing the Bitcoin client RPC.
    pub bitcoind_rpc_client: BitcoinClient,

    /// Handle for accessing the secret service.
    pub s2_client: SecretServiceClient,

    /// Handle for submitting Bitcoin transactions in a stateful manner.
    pub tx_driver: TxDriver,
}
