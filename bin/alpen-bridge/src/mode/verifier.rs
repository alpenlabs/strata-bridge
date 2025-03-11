//! Defines the main loop for the bridge-client in verifier mode.
use tracing::info;

use crate::{config::Config, params::Params};

/// Bootstraps the bridge client in Verifier mode by hooking up all the required auxiliary services
/// including database, p2p client, etc.
pub(crate) async fn bootstrap(_params: Params, _config: Config) -> anyhow::Result<()> {
    info!("bootstrapping verifier node");

    unimplemented!()
}
