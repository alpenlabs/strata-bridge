//! Provides operator wallet initialization.

use std::{num::NonZero, sync::Arc, time::Instant};

use anyhow::anyhow;
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bitcoin::{
    Amount, XOnlyPublicKey,
    hashes::{Hash, sha256},
    relative,
};
use operator_wallet::{NativeGeneralWallet, OperatorWallet, OperatorWalletConfig, sync::Backend};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_common::params::Params;
use strata_bridge_connectors::prelude::{ClaimContestConnector, ClaimPayoutConnector};
use strata_bridge_db::{fdb::client::FdbClient, traits::BridgeDb};
use strata_bridge_exec::output_handles::NativeWallet;
use strata_bridge_primitives::constants::SEGWIT_MIN_AMOUNT;
use strata_bridge_tx_graph::{fee, transactions::prelude::ClaimTx};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::Config;

/// Result of [`init_operator_wallet`] — the constructed wallet plus the per-UTXO
/// denomination of the claim-funding pool. The latter is no longer stored on
/// `OperatorWalletConfig` (the composer is now agnostic of caller denominations); the
/// orchestrator forwards it into `strata_bridge_exec::config::ExecutionConfig` so duty
/// executors can reference the pool by value.
pub(in crate::mode) struct InitializedOperatorWallet {
    /// The composed operator wallet, ready to lease + sign against.
    pub wallet: NativeWallet,
    /// Per-UTXO denomination of the claim-funding pool. The composer is denomination-
    /// agnostic; this value is propagated into `strata_bridge_exec::config::ExecutionConfig`
    /// so duty executors can reference the pool by value.
    pub claim_funding_utxo_value: Amount,
}

pub(in crate::mode) async fn init_operator_wallet(
    config: &Config,
    params: &Params,
    s2_client: &SecretServiceClient,
    db_client: &FdbClient,
) -> anyhow::Result<InitializedOperatorWallet> {
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

    let general_key = s2_client.general_wallet_signer().pubkey().await?;
    info!(%general_key, "operator wallet general key");
    let reserved_key = s2_client.reserved_wallet_signer().pubkey().await?;
    info!(%reserved_key, "operator wallet reserved key");

    let own_covenant_key = s2_client.musig2_signer().pubkey().await?;
    let claim_funding_utxo_value = compute_claim_funding_utxo_value(params, own_covenant_key);
    let operator_wallet_config = OperatorWalletConfig::new(SEGWIT_MIN_AMOUNT, params.network);
    debug!(?operator_wallet_config, %claim_funding_utxo_value, "operator wallet config");

    let general_sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    let reserved_sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    debug!(?general_sync_backend, "operator wallet sync backend");
    let general_wallet =
        NativeGeneralWallet::new(general_key, params.network, general_sync_backend);
    let wallet = OperatorWallet::new(
        general_wallet,
        reserved_key,
        operator_wallet_config,
        reserved_sync_backend,
        leased_outpoints,
    );
    debug!("operator wallet initialized");

    Ok(InitializedOperatorWallet {
        wallet,
        claim_funding_utxo_value,
    })
}

/// Performs a one-shot sync of the operator wallet against its backend.
///
/// Intended to run as a background task at startup so the wallet has a head start before its
/// first on-demand use. A sync failure is logged and swallowed: callers must still sync the wallet
/// before use, so a failed initial sync must not crash the node.
pub(in crate::mode) async fn spawn_initial_operator_wallet_sync(wallet: Arc<RwLock<NativeWallet>>) {
    info!("starting initial operator wallet sync");
    let start = Instant::now();
    match wallet.write().await.sync().await {
        Ok(()) => info!(time_spent=?start.elapsed(), "initial operator wallet sync complete"),
        Err(e) => {
            warn!(?e, time_spent=?start.elapsed(), "initial operator wallet sync failed, first use might be slow")
        }
    }
}

/// Computes the per-UTXO denomination for the claim-funding pool. Each claim transaction
/// consumes one UTXO of this size from the reserved wallet, so the value is derived from
/// the connectors that the claim tx must pay for (which depend on the watchtower set size).
///
/// Not a constant since it depends on the number of watchtowers allowed to contest a claim.
fn compute_claim_funding_utxo_value(params: &Params, own_covenant_key: XOnlyPublicKey) -> Amount {
    // Must match the value used in `orchestrator.rs::COUNTERPROOF_N_DATA`. Hardcoded here too
    // because `Params` does not currently expose it.
    const COUNTERPROOF_N_DATA: NonZero<usize> =
        NonZero::new(128 + 4).expect("counterproof_n_data must be non-zero");

    let network = params.network;

    // The consensus-validity of the following two values do not affect the calculation of the
    // funding amount and so have been set to dummy values instead of hooking this up with other
    // more complicated services to obtain proper values.
    let n_of_n_key = XOnlyPublicKey::from_slice(&[1u8; 32]).expect("must be a valid x-only pubkey");
    let unstaking_image =
        sha256::Hash::from_slice(&[0u8; 32]).expect("must be a valid sha256 hash");

    // NOTE: (@Rajil1213)  Covenant keys are the watchtower keys for the time being until we
    // separate the sets. Exclude the owner — graph construction in `bridge-sm` excludes the owner
    // from watchtowers (see `GraphContext::watchtower_pubkeys`), so the funding amount must
    // too.
    let watchtower_keys: Vec<_> = params
        .keys
        .operators
        .iter()
        .map(|operator| operator.covenant_key())
        .filter(|k| *k != own_covenant_key)
        .collect();
    // cast safety: covenant.len() is bounded by the number of operators, much smaller than u32::MAX
    let n_watchtowers = watchtower_keys.len() as u32;
    let contest_timelock = relative::Height::from_height(params.protocol.contest_timelock);

    let claim_contest_connector = ClaimContestConnector::new(
        network,
        n_of_n_key,
        watchtower_keys,
        contest_timelock,
        fee::claim_contest_surcharge(n_watchtowers, COUNTERPROOF_N_DATA),
    );

    let admin_key = params.keys.admin;
    let claim_payout_connector =
        ClaimPayoutConnector::new(network, n_of_n_key, admin_key, unstaking_image);

    ClaimTx::claim_funds_required(&claim_contest_connector, &claim_payout_connector)
}
