//! Configuration for the P2P.

use std::time::Duration;

use bitcoin::{secp256k1::SecretKey, PublicKey, XOnlyPublicKey};
use libp2p::{Multiaddr, PeerId};
use libp2p_identity::secp256k1::{Keypair as Libp2pSecpKeypair, SecretKey as Libp2pSecpSecretKey};
use strata_p2p_types::OperatorPubKey;

/// Configuration for the P2P.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// [`Libp2pSecpKeypair`] used as [`PeerId`].
    pub keypair: Libp2pSecpKeypair,

    /// Idle connection timeout.
    pub idle_connection_timeout: Duration,

    /// The node's address.
    pub listening_addr: Multiaddr,

    /// List of [`PeerId`]s that the node is allowed to connect to.
    pub allowlist: Vec<PeerId>,

    /// Initial list of nodes to connect to at startup.
    pub connect_to: Vec<Multiaddr>,

    /// List of signers' public keys, whose messages the node is allowed to accept.
    pub signers_allowlist: Vec<OperatorPubKey>,

    /// The number of threads to use for the in memory database.
    ///
    /// Default is [`DEFAULT_NUM_THREADS`](crate::constants::DEFAULT_NUM_THREADS).
    pub num_threads: Option<usize>,
}

impl Configuration {
    /// Creates a new [`Configuration`] by using a [`SecretKey`].
    pub fn new_with_secret_key(
        sk: SecretKey,
        idle_connection_timeout: Duration,
        listening_addr: Multiaddr,
        allowlist: Vec<PeerId>,
        connect_to: Vec<Multiaddr>,
        signers_allowlist: Vec<OperatorPubKey>,
        num_threads: Option<usize>,
    ) -> Self {
        let sk = Libp2pSecpSecretKey::try_from_bytes(sk.secret_bytes()).expect("infallible");
        let keypair = Libp2pSecpKeypair::from(sk);
        Self {
            keypair,
            idle_connection_timeout,
            listening_addr,
            allowlist,
            connect_to,
            signers_allowlist,
            num_threads,
        }
    }

    /// Returns the [`PublicKey`] related to this [`Configuration`].
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_slice(&self.keypair.public().to_bytes()).expect("infallible")
    }

    /// Returns the [`XOnlyPublicKey`] related to this [`Configuration`].
    pub fn x_only_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&self.keypair.public().to_bytes()[1..]).expect("infallible")
    }
}

#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::constants::DEFAULT_IDLE_CONNECTION_TIMEOUT;

    #[test]
    fn new_with_secret_key_works() {
        let keypair = generate_keypair();
        let sk = keypair.secret_key();
        let pk = keypair.public_key();
        let x_only_pk = keypair.x_only_public_key().0;
        let config = Configuration::new_with_secret_key(
            sk,
            Duration::from_secs(DEFAULT_IDLE_CONNECTION_TIMEOUT),
            "/ip4/127.0.0.1/tcp/1234".parse().unwrap(),
            vec![],
            vec![],
            vec![],
            None,
        );
        assert_eq!(config.public_key().inner, pk);
        assert_eq!(config.x_only_public_key(), x_only_pk);
    }
}
