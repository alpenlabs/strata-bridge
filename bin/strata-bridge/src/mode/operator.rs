//! Defines the main loop for the bridge-node in operator mode.

use std::sync::Arc;

use bitcoind_async_client::traits::Reader;
use strata_bridge_db2::fdb::client::FdbClient;
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::{
    config::Config,
    mode::services::{
        btc_client::{init_btc_rpc_client, init_zmq_client},
        operator_table::init_operator_table,
        operator_wallet::init_operator_wallet,
        secret_service::init_secret_service_client,
    },
    params::Params,
};

pub(crate) async fn bootstrap(
    params: Params,
    config: Config,
    db: Arc<FdbClient>,
    _executor: TaskExecutor,
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
    let _operator_wallet = init_operator_wallet(&config, &params, &s2_client, &db).await?;
    info!("operator wallet initialized");

    debug!("initializing bitcoin client");
    let btc_rpc_client = init_btc_rpc_client(&config)?;
    let cur_height = btc_rpc_client.get_block_count().await?;
    info!(%cur_height, "bitcoin client initialized and synced");

    debug!("initializing btc zmq client");
    let zmq_client = init_zmq_client(&config, params.genesis_height).await?;
    let start_height = zmq_client.start_height();
    info!(%start_height, "btc zmq client initialized and subscribed to bitcoin node");

    Ok(())
}
