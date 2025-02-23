//! In-memory persistence for operator's P2P secret data.

use std::future::Future;

use bitcoin::{key::Keypair, XOnlyPublicKey};
use musig2::secp256k1::{schnorr::Signature, Message, PublicKey, SecretKey, SECP256K1};
use secret_service_proto::v1::traits::{P2PSigner, Server};

/// Secret data for the P2P signer.
#[derive(Debug)]
pub struct ServerP2PSigner {
    /// The [`Keypair`] for the P2P signer.
    kp: Keypair,
}

impl ServerP2PSigner {
    /// Creates a new [`ServerP2PSigner`] with the given secret key.
    pub fn new(sk: SecretKey) -> Self {
        let kp = Keypair::from_secret_key(SECP256K1, &sk);
        Self { kp }
    }
}

impl P2PSigner<Server> for ServerP2PSigner {
    fn sign(&self, digest: &[u8; 32]) -> impl Future<Output = Signature> + Send {
        async move { self.kp.sign_schnorr(Message::from_digest(*digest)) }
    }

    fn pubkey(&self) -> impl Future<Output = XOnlyPublicKey> + Send {
        async move { self.kp.x_only_public_key().0 }
    }
}
