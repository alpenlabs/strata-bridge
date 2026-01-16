//! In-memory persistence for operator's P2P secret data.

use libp2p_identity::ed25519::SecretKey;
use secret_service_proto::v2::traits::{Origin, P2PSigner, Server};

/// Secret data for the P2P signer.
#[derive(Debug)]
pub struct ServerP2PSigner {
    /// The [`SecretKey`] for the P2P signer.
    sk: SecretKey,
}

impl ServerP2PSigner {
    /// Creates a new [`ServerP2PSigner`] with the given secret key.
    pub const fn new(sk: SecretKey) -> Self {
        Self { sk }
    }
}

impl P2PSigner<Server> for ServerP2PSigner {
    async fn secret_key(&self) -> <Server as Origin>::Container<SecretKey> {
        self.sk.clone()
    }
}
