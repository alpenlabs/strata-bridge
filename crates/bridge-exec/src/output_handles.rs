//! The handles for external services that need to be accessed by the executors.

use std::{fmt, sync::Arc};

use bitcoin::{Network, XOnlyPublicKey};
use bitcoind_async_client::Client as BitcoinClient;
use btc_tracker::tx_driver::TxDriver;
use jsonrpsee::http_client::HttpClient;
use operator_wallet::{AnyOperatorWallet, NativeGeneralWallet, OperatorWallet};
use secret_service_client::SecretServiceClient;
use strata_bridge_counterproof::BridgeCounterproofHost;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_proof::BridgeProofHost;
use strata_mosaic_client_api::MosaicClientApi;
use tokio::sync::RwLock;

/// The native operator-wallet type. The binary constructs one of these (or a Fireblocks-backed
/// wallet) at startup and erases the choice into [`AnyOperatorWallet`] for [`OutputHandles`].
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
    /// races between concurrent duties. Erased over the backend so the binary can pick native
    /// vs Fireblocks at startup without threading `<G>` through every executor.
    pub wallet: Arc<RwLock<AnyOperatorWallet>>,

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

    /// Operator's general-wallet x-only pubkey. Cached at orchestrator startup so the
    /// CPFP-publishing path doesn't have to round-trip to secret-service on every broadcast.
    /// Used by [`crate::cpfp_adapters::build_wallet_input_signer`] when signing the
    /// operator-owned funding inputs of CPFP children.
    pub operator_general_pubkey: XOnlyPublicKey,

    /// Operator's musig2-signer x-only pubkey (the "btc key" from the operator table).
    /// Every bridge tx that participates in CPFP carries a keyed-Taproot anchor keyed
    /// to this pubkey (see `KeyData::operator_pubkey` in `bridge-sm`, fed from
    /// `OperatorTable::idx_to_btc_key`). Cached at orchestrator startup so
    /// [`crate::cpfp_adapters::infer_anchor_strategy`] can detect anchors without an RPC
    /// hop. (Counterproof/ack txs key their anchors to the operator's watchtower key,
    /// which today equals the musig2 key per `bin/strata-bridge::operator_wallet`'s
    /// watchtower-key note; if those sets ever diverge this needs to grow.)
    pub operator_musig2_pubkey: XOnlyPublicKey,

    /// Bitcoin network — needed alongside [`Self::operator_musig2_pubkey`] to derive the
    /// expected anchor `script_pubkey` for CPFP-strategy inference.
    pub network: Network,
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
