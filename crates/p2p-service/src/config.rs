//! Configuration for the P2P.

use std::time::Duration;

use libp2p::{
    identity::ed25519::{Keypair as Libp2pEdKeypair, SecretKey as Libp2pEdSecretKey},
    Multiaddr, PeerId,
};
use strata_bridge_p2p_types::P2POperatorPubKey;

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
        );
        assert_eq!(config.keypair.to_bytes(), keypair.to_bytes());
    }
}
