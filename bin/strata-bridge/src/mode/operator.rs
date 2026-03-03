//! Defines the main loop for the bridge-node in operator mode.

use std::sync::Arc;

use strata_bridge_db2::fdb::client::FdbClient;
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::config::Config;

pub(crate) async fn bootstrap(
    config: Config,
    _db: Arc<FdbClient>,
    _executor: TaskExecutor,
) -> anyhow::Result<()> {
    info!("starting operator loop");
    debug!(?config, "starting operator loop with provided config");

    Ok(())
}
