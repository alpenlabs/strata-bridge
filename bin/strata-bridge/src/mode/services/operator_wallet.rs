//! Provides operator wallet initialization.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use bdk_bitcoind_rpc::bitcoincore_rpc;
use operator_wallet::{
    AnyOperatorWallet, NativeGeneralWallet, OperatorWallet, OperatorWalletConfig,
    general::fireblocks::{FireblocksConfig, FireblocksGeneralWallet},
    sync::Backend,
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_common::params::Params;
use strata_bridge_db::{fdb::client::FdbClient, traits::BridgeDb};
use strata_bridge_primitives::constants::SEGWIT_MIN_AMOUNT;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::Config;

pub(in crate::mode) async fn init_operator_wallet(
    config: &Config,
    params: &Params,
    s2_client: &SecretServiceClient,
    db_client: &FdbClient,
) -> anyhow::Result<AnyOperatorWallet> {
    info!("fetching leased utxos from database");
    let leased_outpoints = db_client
        .get_all_funds()
        .await
        .map_err(|e| anyhow!("error while fetching leased outpoints from FDB: {e:?}"))?
        .iter()
        .copied()
        .collect();

    let auth = bitcoincore_rpc::Auth::UserPass(
        config.btc_client.user.to_string(),
        config.btc_client.pass.to_string(),
    );
    let bitcoin_rpc_client = Arc::new(
        bitcoincore_rpc::Client::new(config.btc_client.url.as_str(), auth)
            .expect("should be able to create bitcoin client"),
    );
    debug!(?bitcoin_rpc_client, "bitcoin rpc client");

    let reserved_key = s2_client.reserved_wallet_signer().pubkey().await?;
    info!(%reserved_key, "operator wallet reserved key");
    let operator_wallet_config = OperatorWalletConfig::new(SEGWIT_MIN_AMOUNT, params.network);
    debug!(?operator_wallet_config, "operator wallet config");

    // The reserved wallet is always native (BDK), regardless of the general-wallet backend.
    let reserved_sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());

    let wallet: AnyOperatorWallet = match &config.operator_wallet.fireblocks {
        None => {
            let general_key = s2_client.general_wallet_signer().pubkey().await?;
            info!(%general_key, "operator wallet general key (native backend)");
            let general_sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
            let general_wallet =
                NativeGeneralWallet::new(general_key, params.network, general_sync_backend);
            OperatorWallet::new(
                general_wallet,
                reserved_key,
                operator_wallet_config,
                reserved_sync_backend,
                leased_outpoints,
            )
            .into()
        }
        Some(fb) => {
            info!(
                vault = %fb.vault_account_id,
                asset = %fb.asset_id,
                "operator wallet general backend: fireblocks"
            );
            let api_secret = std::fs::read(&fb.api_secret_path).map_err(|e| {
                anyhow!(
                    "failed to read Fireblocks API secret at {:?}: {e}",
                    fb.api_secret_path
                )
            })?;
            let fb_config = FireblocksConfig {
                base_url: fb.base_url.clone(),
                api_key: fb.api_key.clone(),
                vault_account_id: fb.vault_account_id.clone(),
                asset_id: fb.asset_id.clone(),
                network: params.network,
                deposit_address: fb.deposit_address.clone(),
                bip44_address_index: fb.bip44_address_index,
                bip44_change: fb.bip44_change,
            };
            let general_wallet = FireblocksGeneralWallet::new(fb_config, &api_secret)
                .map_err(|e| anyhow!("failed to initialize Fireblocks general wallet: {e}"))?;
            OperatorWallet::new(
                general_wallet,
                reserved_key,
                operator_wallet_config,
                reserved_sync_backend,
                leased_outpoints,
            )
            .into()
        }
    };
    debug!("operator wallet initialized");

    Ok(wallet)
}

/// Interval between attempts when the initial operator wallet sync fails.
const INITIAL_SYNC_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Syncs the operator wallet against its backend until one sync succeeds, then returns.
///
/// Intended to run as a background task at startup. The retry loop matters because syncs
/// are duty-driven after startup: without it, a bitcoind or backend outage at boot leaves
/// the wallet empty, and every CPFP bump fails with `InsufficientFunding` until the first
/// duty happens to call `sync()`. A failed attempt does not crash the node — it is logged
/// and retried, and the health probe reads the outcome through `last_general_sync`.
pub(in crate::mode) async fn spawn_initial_operator_wallet_sync(
    wallet: Arc<RwLock<AnyOperatorWallet>>,
) {
    info!("starting initial operator wallet sync");
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let start = Instant::now();
        // Bind the result so the write guard (a temporary in this expression) drops here.
        // A `match` directly on the expression keeps the guard alive through the arms, and
        // the retry sleep then holds the wallet write lock for the whole interval — every
        // duty and the health probe stall behind it.
        let result = wallet.write().await.sync().await;
        match result {
            Ok(()) => {
                info!(time_spent=?start.elapsed(), attempt, "initial operator wallet sync complete");
                return;
            }
            Err(e) => {
                warn!(
                    ?e,
                    time_spent=?start.elapsed(),
                    attempt,
                    retry_in=?INITIAL_SYNC_RETRY_INTERVAL,
                    "initial operator wallet sync failed; wallet stays unusable until a sync succeeds"
                );
                tokio::time::sleep(INITIAL_SYNC_RETRY_INTERVAL).await;
            }
        }
    }
}
