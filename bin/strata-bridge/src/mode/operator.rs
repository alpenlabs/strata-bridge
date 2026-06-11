//! Defines the main loop for the bridge-node in operator mode.

use std::sync::Arc;

use bitcoind_async_client::traits::Reader;
use strata_bridge_common::params::Params;
use strata_bridge_db::fdb::client::FdbClient;
use strata_tasks::TaskExecutor;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::{
    config::Config,
    mode::{
        rpc_server::init_rpc_server,
        services::{
            asm_rpc::init_asm_rpc_client,
            btc_client::init_btc_rpc_client,
            mosaic_client::{init_mosaic_client, run_mosaic_setup, spawn_mosaic_poller},
            operator_table::init_operator_table,
            operator_wallet::{init_operator_wallet, spawn_initial_operator_wallet_sync},
            orchestrator::init_orchestrator,
            p2p_handles::{P2PHandles, init_p2p_handles},
            secret_service::init_secret_service_client,
        },
    },
};

pub(crate) async fn bootstrap(
    params: Params,
    config: Config,
    db: Arc<FdbClient>,
    executor: TaskExecutor,
) -> anyhow::Result<()> {
    info!("starting operator loop");
    debug!(
        ?params,
        ?config,
        "starting operator loop with provided params and config"
    );

    debug!(config=?config.secret_service_client, "initializing secret service client");
    let s2_client = init_secret_service_client(&config.secret_service_client).await;
    info!("initialized secret service client");

    debug!("initializing full operator table");
    let full_operator_table = init_operator_table(&params, &s2_client).await?;
    let pov_idx = full_operator_table.pov_idx();
    let pov_btc_key = full_operator_table.pov_btc_key();
    let pov_p2p_key = full_operator_table.pov_p2p_key();
    let agg_key = full_operator_table.aggregated_btc_key();
    info!(%pov_idx, %pov_p2p_key, %pov_btc_key, %agg_key, "full operator table initialized");

    debug!("initializing operator wallet");
    let initialized_wallet = init_operator_wallet(&config, &params, &s2_client, &db).await?;
    let claim_funding_utxo_value = initialized_wallet.claim_funding_utxo_value;
    let operator_wallet = Arc::new(RwLock::new(initialized_wallet.wallet));
    info!(%claim_funding_utxo_value, "operator wallet initialized");

    debug!("spawning initial operator wallet sync");
    let sync_wallet = operator_wallet.clone();
    // Sync the wallet on a best-effort basis in the background.
    // This is just to speed up syncing when we actually need to use the funds.
    tokio::spawn(async move { spawn_initial_operator_wallet_sync(sync_wallet).await });
    info!("initial operator wallet sync task spawned");

    debug!("initializing bitcoin client");
    let btc_rpc_client = init_btc_rpc_client(&config)?;
    let cur_height = btc_rpc_client.get_block_count().await?;
    info!(%cur_height, "bitcoin client initialized and synced");

    debug!("initializing asm rpc client");
    let asm_rpc_client = init_asm_rpc_client(&config.asm_rpc);
    info!("asm rpc client initialized");

    debug!("initializing p2p client");
    let P2PHandles {
        command_handle,
        gossip_handle,
        req_resp_handle,
        keypair,
    } = init_p2p_handles(&config, &params, &s2_client, &executor).await?;
    info!("p2p client initialized, connected to swarm and listening");

    debug!("starting rpc server");
    init_rpc_server(&params, &config, db.clone(), command_handle, &executor).await?;
    info!(addr=%config.rpc.rpc_addr, "rpc server started and listening for requests");

    debug!("initializing mosaic client");
    let mosaic_client = Arc::new(init_mosaic_client(
        &config.mosaic,
        &full_operator_table,
        full_operator_table.pov_idx(),
    ));
    info!("mosaic client initialized");

    debug!("running mosaic setup for all operator pairs");
    run_mosaic_setup(mosaic_client.as_ref(), &full_operator_table).await?;
    info!("mosaic setup complete for all operator pairs");

    debug!("starting orchestrator pipeline");
    let mosaic_poller_client = mosaic_client.clone();
    init_orchestrator(
        &params,
        &config,
        full_operator_table,
        &s2_client,
        mosaic_client,
        gossip_handle,
        req_resp_handle,
        keypair,
        operator_wallet,
        claim_funding_utxo_value,
        btc_rpc_client,
        asm_rpc_client,
        db.clone(),
        &executor,
    )
    .await?;

    // Spawn after `init_orchestrator` so the orchestrator's `subscribe_events` call has already
    // registered a subscriber before the poller starts emitting `AdaptorsVerified` events.
    spawn_mosaic_poller(&executor, mosaic_poller_client);
    info!("mosaic watched-deposits poller started");

    debug!("node bootstrapping complete, all services started");
    Ok(())
}
