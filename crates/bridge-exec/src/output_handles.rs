//! The handles for external services that need to be accessed by the executors.

use std::{fmt, sync::Arc};

use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::tx_driver::TxDriver;
use jsonrpsee::http_client::HttpClient;
use operator_wallet::{NativeGeneralWallet, OperatorWallet};
use secret_service_client::SecretServiceClient;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_proof::BridgeProofHost;
use strata_mosaic_client_api::MosaicClientApi;
use tokio::sync::RwLock;

/// Concrete operator-wallet type used by bridge-exec. Today the only general-wallet backend in
/// use is [`NativeGeneralWallet`]; Fireblocks support (STR-3437) will add a sibling impl and
/// the binary will pick between them at startup.
pub type NativeWallet = OperatorWallet<NativeGeneralWallet>;

/// The handles for external services that need to be accessed by the executors.
///
/// If this needs to be shared across multiple executors, it should be wrapped in an
/// [`Arc`].
pub struct OutputHandles {
    /// Handle for accessing operator funds.
    ///
    /// Methods on [`OperatorWallet`] take `&mut self`. The outer `RwLock` also lets executors
    /// span multi-step critical sections (e.g. DB-lookup-then-fund-then-persist) without
    /// races between concurrent duties.
    pub wallet: Arc<RwLock<NativeWallet>>,

    /// Handle for accessing the database.
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2670>
    // Make this generic over `BridgeDb` instead of tying it to `FdbClient`.
    pub db: Arc<FdbClient>,

    /// Handle for broadcasting P2P messages
    pub msg_handler: RwLock<MessageHandler>,

    /// Handle for accessing the Bitcoin client RPC.
    pub bitcoind_rpc_client: BitcoinClient,

    /// Handle for accessing the ASM RPC.
    pub asm_rpc_client: HttpClient,

    /// Handle for accessing the secret service.
    pub s2_client: SecretServiceClient,

    /// Handle for submitting Bitcoin transactions in a stateful manner.
    pub tx_driver: TxDriver,

    /// Handle for accessing the mosaic service.
    ///
    /// Stored as a trait object to keep `OutputHandles` non-generic: the concrete client type
    /// lives in `bin/strata-bridge` (it's parameterized by bin-only resolver types), so pinning
    /// the field to that would force a cascade of `<M: MosaicClientApi>` generics across every
    /// executor entry point and the duty dispatcher. Virtual dispatch is negligible here since
    /// every call hits a network RPC.
    pub mosaic_client: Arc<dyn MosaicClientApi>,

    /// Bridge-wide operator table, used by executors that need to enumerate peers (e.g., to fetch
    /// per-watchtower keys from mosaic).
    pub operator_table: OperatorTable,

    /// Host used to generate bridge proofs.
    pub bridge_proof_host: BridgeProofHost,

    /// Host used to generate bridge counterproofs.
    pub counterproof_host: BridgeCounterproofHost,
}

impl fmt::Debug for OutputHandles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputHandles")
            .field("wallet", &self.wallet)
            .field("db", &self.db)
            .field("msg_handler", &self.msg_handler)
            .field("bitcoind_rpc_client", &self.bitcoind_rpc_client)
            .field("asm_rpc_client", &"<HttpClient>")
            .field("s2_client", &self.s2_client)
            .field("tx_driver", &self.tx_driver)
            .field("mosaic_client", &"<dyn MosaicClientApi>")
            .field("operator_table", &self.operator_table)
            .field("bridge_proof_host", &"<BridgeProofHost>")
            .field("counterproof_host", &"<BridgeCounterproofHost>")
            .finish()
    }
}
