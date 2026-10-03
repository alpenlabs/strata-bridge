//! Configuration for the P2P.

use std::{num::NonZeroUsize, time::Duration};

use libp2p::{
    identity::ed25519::{Keypair as Libp2pEdKeypair, SecretKey as Libp2pEdSecretKey},
    Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::P2POperatorPubKey;

/// Gossipsub peer scoring preset configuration.
///
/// This allows selecting between predefined scoring configurations optimized
/// for different deployment scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipsubScoringPreset {
    /// Use libp2p default scoring parameters.
    ///
    /// This is the recommended setting for production deployments.
    /// It enables standard gossipsub scoring which penalizes misbehaving peers
    /// and maintains network health.
    #[default]
    Default,

    /// Use permissive scoring parameters that disable most penalties.
    ///
    /// This is intended for test networks and development environments where:
    /// - Multiple peers may run on the same IP (localhost testing)
    /// - Small networks may not have enough message traffic
    /// - Scoring penalties would interfere with testing
    ///
    /// **WARNING**: Do not use in production as it disables important peer
    /// quality mechanisms.
    Permissive,
}

/// Configuration for the P2P.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// [`Libp2pEdKeypair`] used as [`PeerId`].
    pub keypair: Libp2pEdKeypair,

    /// Idle connection timeout.
    pub idle_connection_timeout: Option<Duration>,

    /// The node's address.
    pub listening_addr: Multiaddr,

    /// List of [`PeerId`]s that the node is allowed to connect to.
    pub allowlist: Vec<PeerId>,

    /// Initial list of nodes to connect to at startup.
    pub connect_to: Vec<Multiaddr>,

    /// List of signers' public keys, whose messages the node is allowed to accept.
    pub signers_allowlist: Vec<P2POperatorPubKey>,

    /// The number of threads to use for the in memory database.
    ///
    /// Default is [`DEFAULT_NUM_THREADS`](crate::constants::DEFAULT_NUM_THREADS).
    pub num_threads: Option<usize>,

    /// Dial timeout.
    ///
    /// The default is [`DEFAULT_DIAL_TIMEOUT`](strata_p2p::swarm::DEFAULT_DIAL_TIMEOUT).
    pub dial_timeout: Option<Duration>,

    /// General timeout for operations.
    ///
    /// The default is [`DEFAULT_GENERAL_TIMEOUT`](strata_p2p::swarm::DEFAULT_GENERAL_TIMEOUT).
    pub general_timeout: Option<Duration>,

    /// Connection check interval.
    ///
    /// The default is
    /// [`DEFAULT_CONNECTION_CHECK_INTERVAL`](strata_p2p::swarm::DEFAULT_CONNECTION_CHECK_INTERVAL).
    pub connection_check_interval: Option<Duration>,

    /// Target number of peers in the gossipsub mesh.
    ///
    /// Default is 6 (libp2p gossipsub default).
    pub gossipsub_mesh_n: Option<usize>,

    /// Minimum number of peers in the gossipsub mesh before grafting more.
    ///
    /// Default is 5 (libp2p gossipsub default).
    pub gossipsub_mesh_n_low: Option<usize>,

    /// Maximum number of peers in the gossipsub mesh before pruning.
    ///
    /// Default is 12 (libp2p gossipsub default).
    pub gossipsub_mesh_n_high: Option<usize>,

    /// Gossipsub peer scoring preset.
    ///
    /// If `None`, defaults to [`GossipsubScoringPreset::Default`] which uses
    /// libp2p's standard scoring parameters suitable for production.
    ///
    /// Set to [`GossipsubScoringPreset::Permissive`] for test networks where
    /// scoring penalties would interfere with testing (e.g., localhost with
    /// multiple peers on the same IP).
    pub gossipsub_scoring_preset: Option<GossipsubScoringPreset>,

    /// Initial delay before the first gossipsub heartbeat.
    pub gossipsub_heartbeat_initial_delay: Option<Duration>,

    /// The duration a message to be published can wait to be sent before it is abandoned.
    pub gossipsub_publish_queue_duration: Option<Duration>,

    /// The duration a message to be forwarded can wait to be sent before it is abandoned.
    pub gossipsub_forward_queue_duration: Option<Duration>,

    /// Interval between re-dial attempts for peers that have become disconnected.
    ///
    /// A background task wakes up every `peer_reconnect_interval`, queries the swarm for each
    /// peer in `allowlist`, and issues a `ConnectToPeer` command for any peer that is no
    /// longer connected. Defaults to
    /// [`DEFAULT_PEER_RECONNECT_INTERVAL`](crate::constants::DEFAULT_PEER_RECONNECT_INTERVAL).
    pub peer_reconnect_interval: Option<Duration>,

    /// Rate-limit score charged per accepted peer message; see
    /// [`OperatorValidator::message_cost`](crate::validator::OperatorValidator::message_cost).
    ///
    /// Defaults to [`DEFAULT_MESSAGE_COST`](crate::validator::DEFAULT_MESSAGE_COST).
    pub rate_limit_message_cost: Option<f64>,

    /// Rate-limit score below which a peer is muted. Must be negative. See
    /// [`OperatorValidator::mute_threshold`](crate::validator::OperatorValidator::mute_threshold).
    ///
    /// Defaults to [`DEFAULT_MUTE_THRESHOLD`](crate::validator::DEFAULT_MUTE_THRESHOLD).
    pub rate_limit_mute_threshold: Option<f64>,

    /// Rate-limit score a peer recovers per second; see
    /// [`OperatorValidator::recovery_per_sec`](crate::validator::OperatorValidator::recovery_per_sec).
    ///
    /// Defaults to [`DEFAULT_RECOVERY_PER_SEC`](crate::validator::DEFAULT_RECOVERY_PER_SEC).
    pub rate_limit_recovery_per_sec: Option<f64>,

    /// How long a peer that crosses the mute threshold stays muted; see
    /// [`OperatorValidator::mute_duration`](crate::validator::OperatorValidator::mute_duration).
    ///
    /// Defaults to [`DEFAULT_MUTE_DURATION`](crate::validator::DEFAULT_MUTE_DURATION).
    pub rate_limit_mute_duration: Option<Duration>,

    /// Size of the inbound gossip event buffer.
    ///
    /// A consumer that falls this far behind loses the oldest messages, which then have to be
    /// nagged for. Received messages stay resident until overwritten, so memory is about this many
    /// times the message size.
    ///
    /// Defaults to
    /// [`DEFAULT_GOSSIP_EVENT_BUFFER_SIZE`](crate::constants::DEFAULT_GOSSIP_EVENT_BUFFER_SIZE).
    pub gossip_event_buffer_size: Option<NonZeroUsize>,

    /// Size of the outbound gossip command queue.
    ///
    /// Publishing does not wait for space, so messages beyond this are dropped.
    ///
    /// Defaults to
    /// [`DEFAULT_GOSSIP_COMMAND_BUFFER_SIZE`](crate::constants::DEFAULT_GOSSIP_COMMAND_BUFFER_SIZE).
    pub gossip_command_buffer_size: Option<NonZeroUsize>,
}

impl Configuration {
    /// Creates a new [`Configuration`] by using a [`Libp2pEdSecretKey`].
    #[expect(clippy::too_many_arguments)]
    pub fn new_with_secret_key(
        sk: Libp2pEdSecretKey,
        idle_connection_timeout: Option<Duration>,
        listening_addr: Multiaddr,
        allowlist: Vec<PeerId>,
        connect_to: Vec<Multiaddr>,
        signers_allowlist: Vec<P2POperatorPubKey>,
        num_threads: Option<usize>,
        dial_timeout: Option<Duration>,
        general_timeout: Option<Duration>,
        connection_check_interval: Option<Duration>,
        gossipsub_mesh_n: Option<usize>,
        gossipsub_mesh_n_low: Option<usize>,
        gossipsub_mesh_n_high: Option<usize>,
        gossipsub_scoring_preset: Option<GossipsubScoringPreset>,
        gossipsub_heartbeat_initial_delay: Option<Duration>,
        gossipsub_publish_queue_duration: Option<Duration>,
        gossipsub_forward_queue_duration: Option<Duration>,
        peer_reconnect_interval: Option<Duration>,
        rate_limit_message_cost: Option<f64>,
        rate_limit_mute_threshold: Option<f64>,
        rate_limit_recovery_per_sec: Option<f64>,
        rate_limit_mute_duration: Option<Duration>,
        gossip_event_buffer_size: Option<NonZeroUsize>,
        gossip_command_buffer_size: Option<NonZeroUsize>,
    ) -> Self {
        let keypair = Libp2pEdKeypair::from(sk);
        Self {
            keypair,
            idle_connection_timeout,
            listening_addr,
            allowlist,
            connect_to,
            signers_allowlist,
            num_threads,
            dial_timeout,
            general_timeout,
            connection_check_interval,
            gossipsub_mesh_n,
            gossipsub_mesh_n_low,
            gossipsub_mesh_n_high,
            gossipsub_scoring_preset,
            gossipsub_heartbeat_initial_delay,
            gossipsub_publish_queue_duration,
            gossipsub_forward_queue_duration,
            peer_reconnect_interval,
            rate_limit_message_cost,
            rate_limit_mute_threshold,
            rate_limit_recovery_per_sec,
            rate_limit_mute_duration,
            gossip_event_buffer_size,
            gossip_command_buffer_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_with_secret_key_works() {
        let keypair = Libp2pEdKeypair::generate();
        let sk = keypair.secret();
        let config = Configuration::new_with_secret_key(
            sk,
            None,
            "/ip4/127.0.0.1/tcp/1234".parse().unwrap(),
            vec![],
            vec![],
            vec![],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(config.keypair.to_bytes(), keypair.to_bytes());
    }
}
