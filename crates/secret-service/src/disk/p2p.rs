use std::future::Future;

use bitcoin::key::Keypair;
use musig2::secp256k1::{schnorr::Signature, Message, PublicKey, SecretKey, SECP256K1};
use secret_service_proto::v1::traits::{P2PSigner, Server};

pub struct ServerP2PSigner {
    kp: Keypair,
}

impl ServerP2PSigner {
    pub fn new(sk: SecretKey) -> Self {
        let kp = Keypair::from_secret_key(SECP256K1, &sk);
        Self { kp }
    }
}

impl P2PSigner<Server> for ServerP2PSigner {
    fn sign(&self, digest: &[u8; 32]) -> impl Future<Output = Signature> + Send {
        async move {
            self.kp
                .sign_schnorr(Message::from_digest_slice(digest).unwrap())
        }
    }

    fn pubkey(&self) -> impl Future<Output = PublicKey> + Send {
        async move { self.kp.public_key() }
    }
}
