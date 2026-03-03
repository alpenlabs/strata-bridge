//! Defines the main loop for the bridge-node in operator mode.

use std::sync::Arc;

use strata_bridge_db2::fdb::client::FdbClient;
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::{config::Config, params::Params};

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

    Ok(())
}
