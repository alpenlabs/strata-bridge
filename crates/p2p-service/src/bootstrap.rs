//! Module to bootstrap the p2p node by hooking up all the required services.

use std::time::Duration;

use strata_p2p::{
    commands::{Command, ConnectToPeerCommand},
    swarm::{
        self, handle::P2PHandle, P2PConfig, DEFAULT_CONNECTION_CHECK_INTERVAL,
        DEFAULT_DIAL_TIMEOUT, DEFAULT_GENERAL_TIMEOUT, P2P,
    },
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::{config::Configuration, constants::DEFAULT_IDLE_CONNECTION_TIMEOUT};

/// Bootstrap the p2p node by hooking up all the required services.
pub async fn bootstrap(
    config: &Configuration,
) -> anyhow::Result<(P2PHandle, CancellationToken, JoinHandle<()>)> {
    let allowlist_len = config.allowlist.len();

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

    info!("creating a swarm");
    let swarm = swarm::with_tcp_transport(&p2p_config)?;

    info!("creating a p2p node");
    let (mut p2p, handle) = P2P::from_config(p2p_config, cancel.clone(), swarm, None)?;

    info!("establishing connections");
    let _ = p2p.establish_connections().await;

    info!("listening for network events and commands from handles");
    let listen_task = tokio::spawn(p2p.listen());

    let connect_handle = handle.clone();
    let connect_to = config.connect_to.clone();
    let allowlist = config.allowlist.clone();
    let _connect_task = tokio::spawn(async move {
        loop {
            let connected_peers = connect_handle.get_connected_peers().await;
            if connected_peers.len() < allowlist_len {
                debug!(
                    connected_peers=%connected_peers.len(),
                    allowlist=%allowlist_len,
                    "initializing period re-establishing connections"
                );
                for (addr, peer_id) in connect_to.iter().zip(allowlist.iter()) {
                    warn!(
                        %peer_id,
                        "re-connecting to peer"
                    );
                    let command = Command::ConnectToPeer(ConnectToPeerCommand {
                        peer_id: *peer_id,
                        peer_addr: addr.clone(),
                    });
                    let _ = connect_handle.send_command(command).await;
                    debug!(%peer_id, "command sent");
                }
            }
            // TODO(@storopoli): make this configurable
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    Ok((handle, cancel, listen_task))
}
