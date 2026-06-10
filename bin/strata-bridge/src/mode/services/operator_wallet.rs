//! Provides operator wallet initialization.

use std::{sync::Arc, time::Instant};

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

/// Performs a one-shot sync of the operator wallet against its backend.
///
/// Intended to run as a background task at startup so the wallet has a head start before its
/// first on-demand use. A sync failure is logged and swallowed: callers must still sync the wallet
/// before use, so a failed initial sync must not crash the node.
pub(in crate::mode) async fn spawn_initial_operator_wallet_sync(
    wallet: Arc<RwLock<AnyOperatorWallet>>,
) {
    info!("starting initial operator wallet sync");
    let start = Instant::now();
    match wallet.write().await.sync().await {
        Ok(()) => info!(time_spent=?start.elapsed(), "initial operator wallet sync complete"),
        Err(e) => {
            warn!(?e, time_spent=?start.elapsed(), "initial operator wallet sync failed, first use might be slow")
        }
    }
}
