//! Defines the main loop for the bridge-node in operator mode.

use std::sync::Arc;

use strata_bridge_db2::fdb::client::FdbClient;
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::{
    config::Config,
    mode::services::{
        operator_table::init_operator_table, secret_service::init_secret_service_client,
    },
    params::Params,
};

pub(crate) async fn bootstrap(
    params: Params,
    config: Config,
    _db: Arc<FdbClient>,
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
    let operator_table = init_operator_table(params, s2_client).await?;
    let pov_idx = operator_table.pov_idx();
    let pov_btc_key = operator_table.pov_btc_key();
    let pov_p2p_key = operator_table.pov_p2p_key();
    let agg_key = operator_table.aggregated_btc_key();
    info!(%pov_idx, %pov_p2p_key, %pov_btc_key, %agg_key, "operator table initialized");

    Ok(())
}
