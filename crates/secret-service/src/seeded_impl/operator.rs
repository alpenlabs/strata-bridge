//! In-memory persistence for operator's secret data.

use bitcoin::{key::Keypair, XOnlyPublicKey};
use musig2::secp256k1::{schnorr::Signature, Message, SecretKey, SECP256K1};
use secret_service_proto::v1::traits::{OperatorSigner, Origin, Server};

use super::MakeEven;

/// Secret data for the operator.
#[derive(Debug)]
pub struct Operator {
    /// Operator's [`Keypair`] for signing and verifying messages.
    kp: Keypair,
}

impl Operator {
    /// Create a new operator with the given secret key.
    pub fn new(sk: SecretKey) -> Self {
        let kp = Keypair::from_secret_key(SECP256K1, &sk.make_even());
        Self { kp }
    }
}

impl OperatorSigner<Server> for Operator {
    async fn sign(&self, digest: &[u8; 32]) -> <Server as Origin>::Container<Signature> {
        self.kp
            .sign_schnorr(Message::from_digest_slice(digest).unwrap())
    }

    async fn pubkey(&self) -> <Server as Origin>::Container<XOnlyPublicKey> {
        self.kp.x_only_public_key().0
    }
}
