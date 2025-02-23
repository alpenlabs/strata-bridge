use std::future::Future;

use bitcoin::{key::Keypair, XOnlyPublicKey};
use musig2::secp256k1::{schnorr::Signature, Message, PublicKey, SecretKey, SECP256K1};
use secret_service_proto::v1::traits::{OperatorSigner, Origin, Server};

pub struct Operator {
    kp: Keypair,
}

impl Operator {
    pub fn new(sk: SecretKey) -> Self {
        let kp = Keypair::from_secret_key(SECP256K1, &sk);
        Self { kp }
    }
}

impl OperatorSigner<Server> for Operator {
    fn sign(
        &self,
        digest: &[u8; 32],
    ) -> impl Future<Output = <Server as Origin>::Container<Signature>> + Send {
        async move {
            self.kp
                .sign_schnorr(Message::from_digest_slice(digest).unwrap())
        }
    }

    fn pubkey(&self) -> impl Future<Output = <Server as Origin>::Container<XOnlyPublicKey>> + Send {
        async move { self.kp.x_only_public_key().0 }
    }
}
