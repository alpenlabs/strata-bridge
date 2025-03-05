//! In-memory persistence for operator's P2P secret data.

use bitcoin::bip32::Xpriv;
use musig2::secp256k1::{SecretKey, SECP256K1};
use secret_service_proto::v1::traits::{Origin, P2PSigner, Server};
use strata_bridge_primitives::secp::EvenSecretKey;

use super::paths::P2P_KEY_PATH;

/// Secret data for the P2P signer.
#[derive(Debug)]
pub struct ServerP2PSigner {
    /// The [`SecretKey`] for the P2P signer.
    sk: SecretKey,
}

impl ServerP2PSigner {
    /// Creates a new [`ServerP2PSigner`] with the given secret key.
    pub fn new(base: &Xpriv) -> Self {
        let sk = base
            .derive_priv(SECP256K1, &P2P_KEY_PATH)
            .expect("good child key")
            .private_key;
        Self {
            sk: *EvenSecretKey::from(sk),
        }
    }
}

impl P2PSigner<Server> for ServerP2PSigner {
    async fn secret_key(&self) -> <Server as Origin>::Container<SecretKey> {
        self.sk
    }
}
