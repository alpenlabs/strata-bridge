//! The handles for external services that need to be accessed by the executors.

use std::{fmt, sync::Arc};

use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::tx_driver::TxDriver;
use jsonrpsee::http_client::HttpClient;
use operator_wallet::{OperatorWallet, SqliteStore};
use secret_service_client::SecretServiceClient;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_proof::BridgeProofHost;
use strata_mosaic_client_api::MosaicClientApi;
use tokio::sync::{Mutex, RwLock};

/// The handles for external services that need to be accessed by the executors.
///
/// If this needs to be shared across multiple executors, it should be wrapped in an
/// [`Arc`].
pub struct OutputHandles {
    /// Handle for accessing operator funds.
    ///
    /// Selection takes the exclusive guard, which makes the read of the held outpoints, the
    /// choice, and the lease one step. A duty may keep that guard across a multi-step critical
    /// section (e.g. sync-then-DB-lookup-then-fund-then-persist). Signing never runs under
    /// either guard: a duty takes [`OperatorWallet::general_signer`], releases the guard, and then
    /// signs, so a wait on an external signer stalls no other duty.
    pub wallet: Arc<RwLock<OperatorWallet<SqliteStore>>>,

    /// Allows one claim-funding refill at a time.
    ///
    /// A refill signs and broadcasts with no wallet guard held, so this lock is what makes a duty
    /// that finds the pool empty wait for the outputs of the running refill and not fund a second
    /// one. Selection from a pool that has a free output never takes it.
    pub claim_funding_refill: Mutex<()>,

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
            .field("bridge_proof_host", &"<BridgeProofHost>")
            .field("counterproof_host", &"<BridgeCounterproofHost>")
            .finish()
    }
}
