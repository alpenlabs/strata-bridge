//! Provides operator wallet initialization.

use std::sync::Arc;

use anyhow::anyhow;
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bitcoin::{
    Amount, XOnlyPublicKey,
    hashes::{Hash, sha256},
    relative,
};
use operator_wallet::{OperatorWallet, OperatorWalletConfig, sync::Backend};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_connectors::{
    Connector,
    prelude::{ClaimContestConnector, ClaimPayoutConnector},
};
use strata_bridge_db::{fdb::client::FdbClient, traits::BridgeDb};
use strata_bridge_primitives::constants::SEGWIT_MIN_AMOUNT;
use tracing::{debug, info};

use crate::{config::Config, params::Params};

pub(in crate::mode) async fn init_operator_wallet(
    config: &Config,
    params: &Params,
    s2_client: &SecretServiceClient,
    db_client: &FdbClient,
) -> anyhow::Result<OperatorWallet> {
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
    let stakechain_key = s2_client.stakechain_wallet_signer().pubkey().await?;
    info!(%stakechain_key, "operator wallet stakechain key");
    let operator_funds = compute_funding_amount(params);
    let operator_wallet_config = OperatorWalletConfig::new(
        operator_funds,
        SEGWIT_MIN_AMOUNT,
        params.protocol.stake_amount,
        params.network,
    );
    debug!(?operator_wallet_config, "operator wallet config");

    let sync_backend = Backend::BitcoinCore(bitcoin_rpc_client.clone());
    debug!(?sync_backend, "operator wallet sync backend");
    let operator_wallet = OperatorWallet::new(
        general_key,
        stakechain_key,
        operator_wallet_config,
        sync_backend,
        leased_outpoints,
    );
    debug!("operator wallet initialized");

    Ok(operator_wallet)
}

/// Computes the funding amount for the transaction graph based on the nature of the graph being
/// constructed.
///
/// This amount is not a constant since it depends upon the number of watchtowers that are allowed
/// to contest a claim.
fn compute_funding_amount(params: &Params) -> Amount {
    let network = params.network;

    // The consensus-validity of the following two values do not affect the calculation of the
    // funding amount and so have been set to dummy values instead of hooking this up with other
    // more complicated services to obtain proper values.
    let n_of_n_key = XOnlyPublicKey::from_slice(&[1u8; 32]).expect("must be a valid x-only pubkey");
    let unstaking_image =
        sha256::Hash::from_slice(&[0u8; 32]).expect("must be a valid sha256 hash");

    // NOTE: (@Rajil1213)  musig2 keys are the watchtower keys for the time being until we separate
    // the sets
    let watchtower_keys = params.keys.covenant.iter().map(|c| c.musig2).collect();
    let contest_timelock = relative::Height::from_height(params.protocol.contest_timelock);

    let claim_contest_connector =
        ClaimContestConnector::new(network, n_of_n_key, watchtower_keys, contest_timelock);

    let admin_key = params.keys.admin;
    let claim_payout_connector =
        ClaimPayoutConnector::new(network, n_of_n_key, admin_key, unstaking_image);

    claim_contest_connector.value() + claim_payout_connector.value()
}
