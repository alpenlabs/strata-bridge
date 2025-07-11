//! Defines the main loop for the bridge-client in verifier mode.
use strata_tasks::TaskExecutor;
use tracing::info;

use crate::{config::Config, params::Params};

/// Bootstraps the bridge client in Verifier mode by hooking up all the required auxiliary services
/// including database, rpc server, graceful shutdown handler, etc.
pub(crate) async fn bootstrap(
    _params: Params,
    _config: Config,
    _executor: TaskExecutor,
) -> anyhow::Result<()> {
    info!("bootstrapping verifier node");

    unimplemented!()
}
