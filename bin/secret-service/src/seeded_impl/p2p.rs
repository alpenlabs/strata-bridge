//! In-memory persistence for operator's P2P secret data.

use bitcoin::{
    bip32::Xpriv,
    key::{Keypair, TapTweak},
    TapNodeHash, XOnlyPublicKey,
};
use musig2::secp256k1::{schnorr::Signature, Message, SECP256K1};
use secret_service_proto::v2::traits::{Origin, SchnorrSigner, Server};
use strata_bridge_primitives::secp::EvenSecretKey;

use super::paths::P2P_KEY_PATH;

/// Secret data for the P2P signer.
#[derive(Debug)]
pub struct ServerP2PSigner {
    /// The [`SecretKey`] for the P2P signer.
    kp: Keypair,
}

impl ServerP2PSigner {
    /// Creates a new [`ServerP2PSigner`] with the given secret key.
    pub fn new(base: &Xpriv) -> Self {
        let sk: EvenSecretKey = base
            .derive_priv(SECP256K1, &P2P_KEY_PATH)
            .expect("good child key")
            .private_key
            .into();
        let kp = sk.keypair(SECP256K1);
        Self { kp }
    }
}

impl SchnorrSigner<Server> for ServerP2PSigner {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Server as Origin>::Container<Signature> {
        self.kp
            .tap_tweak(SECP256K1, tweak)
            .to_keypair()
            .sign_schnorr(Message::from_digest_slice(digest).expect("digest is 32 bytes"))
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Server as Origin>::Container<Signature> {
        self.kp
            .sign_schnorr(Message::from_digest_slice(digest).expect("digest is exactly 32 bytes"))
    }

    async fn pubkey(&self) -> <Server as Origin>::Container<XOnlyPublicKey> {
        self.kp.x_only_public_key().0
    }
}
