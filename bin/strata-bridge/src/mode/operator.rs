//! Defines the main loop for the bridge-node in operator mode.

use std::sync::Arc;

use bitcoind_async_client::traits::Reader;
use strata_bridge_db::fdb::client::FdbClient;
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::{
    config::Config,
    mode::services::{
        btc_client::init_btc_rpc_client,
        operator_table::init_operator_table,
        operator_wallet::init_operator_wallet,
        orchestrator::init_orchestrator,
        p2p_handles::{P2PHandles, init_p2p_handles},
        rpc_server::init_rpc_server,
        secret_service::init_secret_service_client,
    },
    params::Params,
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

    debug!("initializing operator table");
    let operator_table = init_operator_table(&params, &s2_client).await?;
    let pov_idx = operator_table.pov_idx();
    let pov_btc_key = operator_table.pov_btc_key();
    let pov_p2p_key = operator_table.pov_p2p_key();
    let agg_key = operator_table.aggregated_btc_key();
    info!(%pov_idx, %pov_p2p_key, %pov_btc_key, %agg_key, "operator table initialized");

    debug!("initializing operator wallet");
    let operator_wallet = init_operator_wallet(&config, &params, &s2_client, &db).await?;
    info!("operator wallet initialized");

    debug!("initializing bitcoin client");
    let btc_rpc_client = init_btc_rpc_client(&config)?;
    let cur_height = btc_rpc_client.get_block_count().await?;
    info!(%cur_height, "bitcoin client initialized and synced");

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

    debug!("starting orchestrator pipeline");
    init_orchestrator(
        &params,
        &config,
        operator_table,
        &s2_client,
        gossip_handle,
        req_resp_handle,
        keypair,
        operator_wallet,
        btc_rpc_client,
        db.clone(),
        &executor,
    )
    .await?;

    debug!("node bootstrapping complete, all services started");
    Ok(())
}
