//! Module to bootstrap the p2p node by hooking up all the required services.

use std::time::Duration;

use strata_p2p::swarm::{
    self, handle::P2PHandle, P2PConfig, DEFAULT_CONNECTION_CHECK_INTERVAL, DEFAULT_DIAL_TIMEOUT,
    DEFAULT_GENERAL_TIMEOUT, P2P,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{config::Configuration, constants::DEFAULT_IDLE_CONNECTION_TIMEOUT};

/// Bootstrap the p2p node by hooking up all the required services.
pub async fn bootstrap(
    config: &Configuration,
) -> anyhow::Result<(P2PHandle, CancellationToken, JoinHandle<()>)> {
    let p2p_config = P2PConfig {
        keypair: config.keypair.clone(),
        idle_connection_timeout: config
            .idle_connection_timeout
            .unwrap_or(Duration::from_secs(DEFAULT_IDLE_CONNECTION_TIMEOUT)),
        max_retries: None,
        listening_addr: config.listening_addr.clone(),
        allowlist: config.allowlist.clone(),
        connect_to: config.connect_to.clone(),
        signers_allowlist: config.signers_allowlist.clone(),
        dial_timeout: Some(config.dial_timeout.unwrap_or(DEFAULT_DIAL_TIMEOUT)),
        general_timeout: Some(config.general_timeout.unwrap_or(DEFAULT_GENERAL_TIMEOUT)),
        connection_check_interval: Some(
            config
                .connection_check_interval
                .unwrap_or(DEFAULT_CONNECTION_CHECK_INTERVAL),
        ),
    };
    let cancel = CancellationToken::new();

    info!("initializing swarm");
    let swarm = swarm::with_tcp_transport(&p2p_config)?;
    debug!("swarm initialized");

    info!("initializing p2p node");
    let (mut p2p, handle) = P2P::from_config(p2p_config, cancel.clone(), swarm, None)?;
    debug!("p2p node initialized");

    info!("establishing connections");
    let _ = p2p.establish_connections().await;
    debug!("connections established");

    info!("listening for network events and commands");
    let listen_task = tokio::spawn(p2p.listen());

    Ok((handle, cancel, listen_task))
}
