//! Module to bootstrap the p2p node by hooking up all the required services.

use std::time::Duration;

use strata_p2p::swarm::{
    self,
    handle::{CommandHandle, GossipHandle, ReqRespHandle},
    P2PConfig, DEFAULT_CONNECTION_CHECK_INTERVAL, DEFAULT_DIAL_TIMEOUT, DEFAULT_GENERAL_TIMEOUT,
    P2P,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{config::Configuration, constants::DEFAULT_IDLE_CONNECTION_TIMEOUT};

/// Handles returned after bootstrapping the p2p node.
#[derive(Debug)]
pub struct BootstrapHandles {
    /// Handle to send commands to the p2p node.
    pub command_handle: CommandHandle,
    /// Handle to interact with the gossip protocol.
    pub gossip_handle: GossipHandle,
    /// Handle to interact with the request-response protocol.
    pub req_resp_handle: ReqRespHandle,
    /// Cancellation token to stop the p2p node.
    pub cancel: CancellationToken,
    /// Task handle for the p2p node listener.
    pub listen_task: JoinHandle<()>,
}

/// Bootstrap the p2p node by hooking up all the required services.
pub async fn bootstrap(config: &Configuration) -> anyhow::Result<BootstrapHandles> {
    let p2p_config = P2PConfig {
        transport_keypair: config.keypair.clone().into(),
        idle_connection_timeout: config
            .idle_connection_timeout
            .unwrap_or(Duration::from_secs(DEFAULT_IDLE_CONNECTION_TIMEOUT)),
        max_retries: None,
        listening_addrs: vec![config.listening_addr.clone()],
        connect_to: config.connect_to.clone(),
        dial_timeout: Some(config.dial_timeout.unwrap_or(DEFAULT_DIAL_TIMEOUT)),
        general_timeout: Some(config.general_timeout.unwrap_or(DEFAULT_GENERAL_TIMEOUT)),
        connection_check_interval: Some(
            config
                .connection_check_interval
                .unwrap_or(DEFAULT_CONNECTION_CHECK_INTERVAL),
        ),
        protocol_name: None,
        channel_timeout: None,
        gossipsub_topic: None,
        gossipsub_max_transmit_size: None,
        gossipsub_score_params: None,
        gossipsub_score_thresholds: None,
        gossipsub_mesh_n: config.gossipsub_mesh_n,
        gossipsub_mesh_n_low: config.gossipsub_mesh_n_low,
        gossipsub_mesh_n_high: config.gossipsub_mesh_n_high,
        gossip_event_buffer_size: None,
        commands_event_buffer_size: None,
        command_buffer_size: None,
        handle_default_timeout: None,
        req_resp_event_buffer_size: None,
        req_resp_command_buffer_size: None,
        request_max_bytes: None,
        response_max_bytes: None,
        gossip_command_buffer_size: None,
        envelope_max_age: None,
        max_clock_skew: None,
        kad_protocol_name: None,
        kad_record_ttl: None,
        kad_timer_putrecorderror: None,
        conn_limits: Default::default(),
    };
    let cancel = CancellationToken::new();

    info!("initializing swarm");
    let swarm = swarm::with_default_transport(&p2p_config)?;
    debug!("swarm initialized");

    info!("initializing p2p node");
    let (mut p2p, req_resp_handle) =
        P2P::from_config(p2p_config, cancel.clone(), swarm, None, None)?;
    let command_handle = p2p.new_command_handle();
    let gossip_handle = p2p.new_gossip_handle();
    debug!("p2p node initialized");

    info!("establishing connections");
    let _ = p2p.establish_connections().await;
    debug!("connections established");

    info!("listening for network events and commands");
    let listen_task = tokio::spawn(p2p.listen());

    Ok(BootstrapHandles {
        command_handle,
        gossip_handle,
        req_resp_handle,
        cancel,
        listen_task,
    })
}
