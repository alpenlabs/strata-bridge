//! In-memory persistence for operator's P2P secret data.

use bitcoin::bip32::Xpriv;
use ed25519::signature::Signer;
use ed25519_dalek::SigningKey;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v2::traits::{Ed25519Signer, Origin, Server};

use super::paths::P2P_KEY_PATH;

/// Secret data for the P2P signer.
#[derive(Debug)]
pub struct ServerP2PSigner {
    sk: SigningKey,
}

impl ServerP2PSigner {
    /// Creates a new [`ServerP2PSigner`] with the given base xpriv.
    pub fn new(base: &Xpriv) -> Self {
        let seed = base
            .derive_priv(SECP256K1, &P2P_KEY_PATH)
            .expect("good child key")
            .to_priv()
            .inner
            .secret_bytes();

        let sk = SigningKey::from_bytes(&seed);
        Self { sk }
    }
}

impl Ed25519Signer<Server> for ServerP2PSigner {
    async fn sign(&self, digest: &[u8; 32]) -> <Server as Origin>::Container<ed25519::Signature> {
        self.sk.sign(digest)
    }

    async fn pubkey(&self) -> <Server as Origin>::Container<[u8; 32]> {
        self.sk.verifying_key().to_bytes()
    }
}
