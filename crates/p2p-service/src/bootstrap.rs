//! Module to bootstrap the p2p node by hooking up all the required services.

use std::time::Duration;

use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds, Sha256Topic, TopicScoreParams};
use strata_p2p::swarm::{
    self,
    handle::{CommandHandle, GossipHandle, ReqRespHandle},
    P2PConfig, DEFAULT_CONNECTION_CHECK_INTERVAL, DEFAULT_DIAL_TIMEOUT, DEFAULT_GENERAL_TIMEOUT,
    P2P,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{
    config::{Configuration, GossipsubScoringPreset},
    constants::DEFAULT_IDLE_CONNECTION_TIMEOUT,
};

/// The default gossipsub topic name (must match strata-p2p's default).
const DEFAULT_GOSSIPSUB_TOPIC: &str = "strata";

/// Maximum transmit size for gossipsub messages (8 MB).
///
/// Bridge protocol messages (especially deposit setup with WOTS signatures)
/// can exceed the default 512 KB limit, so we increase this significantly.
const GOSSIPSUB_MAX_TRANSMIT_SIZE: usize = 8 * 1024 * 1024;

/// Creates permissive peer score parameters that don't penalize peers.
///
/// The default libp2p gossipsub scoring has penalties that cause issues in small/test networks:
/// - Mesh message deliveries deficit: penalizes peers that don't deliver enough messages
/// - IP colocation factor: penalizes multiple peers on the same IP (e.g., localhost testing)
///
/// This function disables these penalties while keeping basic topic scoring enabled.
fn create_permissive_peer_score_params(topic_name: &str) -> PeerScoreParams {
    let topic = Sha256Topic::new(topic_name);

    let mut params = PeerScoreParams {
        // Disable IP colocation penalty (important for localhost testing)
        ip_colocation_factor_weight: 0.0,
        // Disable behaviour penalty
        behaviour_penalty_weight: 0.0,
        ..Default::default()
    };

    // Configure topic with disabled penalties but valid structure
    params.topics.insert(
        topic.hash(),
        TopicScoreParams {
            // Keep topic weight at 1.0 so the topic contributes to scoring
            topic_weight: 1.0,

            // Positive scoring for time in mesh (small bonus)
            time_in_mesh_weight: 0.01,
            time_in_mesh_quantum: Duration::from_secs(1),
            time_in_mesh_cap: 10.0,

            // Positive scoring for first message deliveries (small bonus)
            first_message_deliveries_weight: 1.0,
            first_message_deliveries_decay: 0.5,
            first_message_deliveries_cap: 10.0,

            // DISABLE mesh message deliveries penalty (the main issue!)
            mesh_message_deliveries_weight: 0.0,
            mesh_message_deliveries_decay: 0.0,
            mesh_message_deliveries_threshold: 0.0,
            mesh_message_deliveries_cap: 0.0,
            mesh_message_deliveries_activation: Duration::from_secs(1),
            mesh_message_deliveries_window: Duration::from_millis(10),

            // Disable mesh failure penalty
            mesh_failure_penalty_weight: 0.0,
            mesh_failure_penalty_decay: 0.0,

            // Disable invalid message deliveries penalty
            invalid_message_deliveries_weight: 0.0,
            invalid_message_deliveries_decay: 0.0,
        },
    );

    params
}

/// Creates permissive peer score thresholds.
///
/// These thresholds are set low enough that peers with slightly negative scores
/// are still allowed to participate in gossip and publishing.
const fn create_permissive_peer_score_thresholds() -> PeerScoreThresholds {
    PeerScoreThresholds {
        // Allow peers with scores down to -1000 to participate in gossip
        gossip_threshold: -1000.0,
        // Allow peers with scores down to -1000 to receive published messages
        publish_threshold: -1000.0,
        // Only graylist peers with extremely negative scores
        graylist_threshold: -10000.0,
        // Disable opportunistic grafting threshold
        accept_px_threshold: 0.0,
        opportunistic_graft_threshold: 0.0,
    }
}

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
    // Determine scoring parameters based on preset
    let preset = config.gossipsub_scoring_preset.unwrap_or_default();
    let (gossipsub_score_params, gossipsub_score_thresholds) = match preset {
        GossipsubScoringPreset::Default => {
            // Use libp2p defaults (None values)
            (None, None)
        }
        GossipsubScoringPreset::Permissive => {
            // Use permissive parameters for test networks
            (
                Some(create_permissive_peer_score_params(DEFAULT_GOSSIPSUB_TOPIC)),
                Some(create_permissive_peer_score_thresholds()),
            )
        }
    };

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
        gossipsub_max_transmit_size: Some(GOSSIPSUB_MAX_TRANSMIT_SIZE),
        gossipsub_score_params,
        gossipsub_score_thresholds,
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
