//! Defines the main loop for the bridge-node in operator mode.

use std::sync::Arc;

use bitcoind_async_client::traits::Reader;
use strata_bridge_common::params::Params;
use strata_bridge_db::fdb::client::FdbClient;
use strata_tasks::TaskExecutor;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

use crate::{
    config::Config,
    constants::DEFAULT_HEALTH_PROBE_INTERVAL,
    health::{
        COMPONENT_ASM_RPC, COMPONENT_BITCOIN_RPC, COMPONENT_MOSAIC, COMPONENT_P2P, COMPONENT_S2,
        COMPONENT_WALLET, HealthRegistry,
    },
    mode::{
        rpc_server::init_rpc_server,
        services::{
            asm_rpc::init_asm_rpc_client,
            btc_client::init_btc_rpc_client,
            health_probes::{
                spawn_asm_rpc_probe, spawn_bitcoin_rpc_probe, spawn_fdb_probe, spawn_mosaic_probe,
                spawn_p2p_probe, spawn_s2_probe, spawn_wallet_probe,
            },
            mosaic_client::{init_mosaic_client, run_mosaic_setup, spawn_mosaic_poller},
            operator_table::init_operator_table,
            operator_wallet::{init_operator_wallet, spawn_initial_operator_wallet_sync},
            orchestrator::{build_sm_config, init_orchestrator},
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
    health_registry: HealthRegistry,
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

    debug!("initializing operator table");
    let operator_table = init_operator_table(&params, &s2_client).await?;
    let pov_idx = operator_table.pov_idx();
    let pov_btc_key = operator_table.pov_btc_key();
    let pov_p2p_key = operator_table.pov_p2p_key();
    let agg_key = operator_table.aggregated_btc_key();
    info!(%pov_idx, %pov_p2p_key, %pov_btc_key, %agg_key, "operator table initialized");
    health_registry.mark_ok(COMPONENT_S2, "operator_table_loaded");

    debug!("initializing operator wallet");
    let initialized_wallet = init_operator_wallet(&config, &params, &s2_client, &db).await?;
    let claim_funding_utxo_value = initialized_wallet.claim_funding_utxo_value;
    let operator_wallet = Arc::new(RwLock::new(initialized_wallet.wallet));
    info!(%claim_funding_utxo_value, "operator wallet initialized");
    health_registry.mark_ok(COMPONENT_WALLET, "wallet_initialized");

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
    health_registry.mark_ok(COMPONENT_BITCOIN_RPC, "block_count_read");

    debug!("initializing asm rpc client");
    let asm_rpc_client = init_asm_rpc_client(&config.asm_rpc);
    info!("asm rpc client initialized");
    health_registry.mark_degraded(COMPONENT_ASM_RPC, "client_initialized_not_checked");

    debug!("initializing p2p client");
    let P2PHandles {
        command_handle,
        gossip_handle,
        req_resp_handle,
        keypair,
    } = init_p2p_handles(&config, &params, &s2_client, &executor).await?;
    info!("p2p client initialized, connected to swarm and listening");
    health_registry.mark_ok(COMPONENT_P2P, "swarm_initialized");

    debug!("starting rpc server");
    init_rpc_server(
        &params,
        &config,
        db.clone(),
        command_handle.clone(),
        &executor,
        health_registry.clone(),
    )
    .await?;
    info!(addr=%config.rpc.rpc_addr, "rpc server started and listening for requests");

    debug!("initializing mosaic client");
    let mosaic_client = Arc::new(init_mosaic_client(
        &config.mosaic,
        &operator_table,
        operator_table.pov_idx(),
    ));
    info!("mosaic client initialized");
    health_registry.mark_degraded(COMPONENT_MOSAIC, "setup_pending");

    debug!("running mosaic setup for all operator pairs");
    if let Err(err) = run_mosaic_setup(mosaic_client.as_ref(), &operator_table).await {
        health_registry.mark_unhealthy(COMPONENT_MOSAIC, "setup_failed");
        error!(%err, "mosaic setup failed");
        return Err(err);
    }
    info!("mosaic setup complete for all operator pairs");
    health_registry.mark_ok(COMPONENT_MOSAIC, "setup_complete");

    let probe_interval = DEFAULT_HEALTH_PROBE_INTERVAL;
    let expected_peer_count = operator_table.cardinality().saturating_sub(1);
    let sm_config = build_sm_config(&config, &params);
    spawn_fdb_probe(
        db.clone(),
        sm_config,
        probe_interval,
        health_registry.clone(),
    );
    spawn_bitcoin_rpc_probe(
        btc_rpc_client.clone(),
        probe_interval,
        health_registry.clone(),
    );
    spawn_asm_rpc_probe(
        asm_rpc_client.clone(),
        probe_interval,
        health_registry.clone(),
    );
    spawn_p2p_probe(
        command_handle.clone(),
        expected_peer_count,
        probe_interval,
        health_registry.clone(),
    );
    spawn_mosaic_probe(
        mosaic_client.clone(),
        probe_interval,
        health_registry.clone(),
    );
    spawn_s2_probe(s2_client.clone(), probe_interval, health_registry.clone());
    spawn_wallet_probe(
        operator_wallet.clone(),
        probe_interval,
        health_registry.clone(),
    );

    debug!("starting orchestrator pipeline");
    let mosaic_poller_client = mosaic_client.clone();
    init_orchestrator(
        &params,
        &config,
        operator_table,
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
        health_registry.clone(),
    )
    .await?;

    // Spawn after `init_orchestrator` so the orchestrator's `subscribe_events` call has already
    // registered a subscriber before the poller starts emitting `AdaptorsVerified` events.
    spawn_mosaic_poller(&executor, mosaic_poller_client);
    info!("mosaic watched-deposits poller started");

    debug!("node bootstrapping complete, all services started");
    Ok(())
}
