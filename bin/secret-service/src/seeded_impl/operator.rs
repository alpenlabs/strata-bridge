//! In-memory persistence for operator's secret data.

use bitcoin::{bip32::Xpriv, key::Keypair, XOnlyPublicKey};
use musig2::secp256k1::{schnorr::Signature, Message, SECP256K1};
use secret_service_proto::v1::traits::{OperatorSigner, Origin, Server};
use strata_bridge_primitives::secp::EvenSecretKey;

use super::paths::OPERATOR_KEY_PATH;

/// Secret data for the operator.
#[derive(Debug)]
pub struct Operator {
    /// Operator's [`Keypair`] for signing and verifying messages.
    kp: Keypair,
}

impl Operator {
    /// Create a new operator with the given base xpriv.
    pub fn new(base: &Xpriv) -> Self {
        let xp = base
            .derive_priv(SECP256K1, &OPERATOR_KEY_PATH)
            .expect("good child key");
        let kp = Keypair::from_secret_key(SECP256K1, &EvenSecretKey::from(xp.private_key));
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
