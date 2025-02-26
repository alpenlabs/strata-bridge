//! In-memory persistence for operator's P2P secret data.

use musig2::secp256k1::SecretKey;
use secret_service_proto::v1::traits::{Origin, P2PSigner, Server};

use super::MakeEven;

/// Secret data for the P2P signer.
#[derive(Debug)]
pub struct ServerP2PSigner {
    /// The [`SecretKey`] for the P2P signer.
    sk: SecretKey,
}

impl ServerP2PSigner {
    /// Creates a new [`ServerP2PSigner`] with the given secret key.
    pub fn new(sk: SecretKey) -> Self {
        Self { sk: sk.make_even() }
    }
}

impl P2PSigner<Server> for ServerP2PSigner {
    async fn secret_key(&self) -> <Server as Origin>::Container<SecretKey> {
        self.sk
    }
}
