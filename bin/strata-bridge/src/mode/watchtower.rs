//! Defines the main loop for the bridge-client in watchtower mode.
use strata_tasks::TaskExecutor;
use tracing::info;

use crate::{config::Config, params::Params};

/// Bootstraps the bridge client in watchtower mode by hooking up all the required auxiliary
/// services including database, rpc server, graceful shutdown handler, etc.
///
/// NOTE: (@Rajil1213) this is currently a stub and will be implemented in the future.
pub(crate) async fn bootstrap(
    _params: Params,
    _config: Config,
    _executor: TaskExecutor,
) -> anyhow::Result<()> {
    info!("bootstrapping watchtower node");

    unimplemented!()
}
