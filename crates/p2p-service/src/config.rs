//! Configuration for the P2P.

use std::time::Duration;

use libp2p::{
    identity::ed25519::{Keypair as Libp2pEdKeypair, SecretKey as Libp2pEdSecretKey},
    Multiaddr, PeerId,
};
use serde::{Deserialize, Serialize};
use strata_bridge_p2p_types::P2POperatorPubKey;

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
        );
        assert_eq!(config.keypair.to_bytes(), keypair.to_bytes());
    }
}
