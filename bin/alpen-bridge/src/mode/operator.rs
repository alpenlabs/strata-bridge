//! Defines the main loop for the bridge-client in operator mode.
use tracing::info;

use crate::{args::Cli, config::Config, params::Params};

/// Bootstraps the bridge client in Operator mode by hooking up all the required auxiliary services
/// including database, rpc server, etc.pub(crate) async fn bootstrap() -> anyhow::Result<()> {
pub(crate) async fn bootstrap(params: Params, config: Config) -> anyhow::Result<()> {
    info!("bootstrapping operator node");

    unimplemented!("IMPLEMENT ME!");
}
