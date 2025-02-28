//! Configuration for the P2P.

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use libp2p_identity::secp256k1::Keypair as Libp2pSecpKeypair;
use strata_p2p_types::OperatorPubKey;

/// Configuration for the P2P.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// [`Keypair`] used as [`PeerId`].
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
    /// Default is [`DEFAULT_NUM_THREADS`].
    pub num_threads: Option<usize>,
}
