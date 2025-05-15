//! In-memory persistence for operator's secret data.

use bitcoin::{
    bip32::Xpriv,
    key::{Keypair, TapTweak},
    TapNodeHash, XOnlyPublicKey,
};
use musig2::secp256k1::{schnorr::Signature, Message, SECP256K1};
use secret_service_proto::v1::traits::{Origin, Server, WalletSigner};
use strata_bridge_primitives::secp::EvenSecretKey;

use super::paths::{GENERAL_WALLET_KEY_PATH, STAKECHAIN_WALLET_KEY_PATH};

/// General wallet signer in-memory implementation.
#[derive(Debug)]
pub struct GeneralWalletSigner {
    /// [`Keypair`] for signing messages.
    kp: Keypair,
}

impl GeneralWalletSigner {
    /// Create a new operator with the given base xpriv.
    pub fn new(base: &Xpriv) -> Self {
        let xp = base
            .derive_priv(SECP256K1, &GENERAL_WALLET_KEY_PATH)
            .expect("good child key");
        let kp = Keypair::from_secret_key(SECP256K1, &EvenSecretKey::from(xp.private_key));
        Self { kp }
    }
}

impl WalletSigner<Server> for GeneralWalletSigner {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Server as Origin>::Container<Signature> {
        self.kp
            .tap_tweak(SECP256K1, tweak)
            .to_keypair()
            .sign_schnorr(Message::from_digest_slice(digest).unwrap())
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Server as Origin>::Container<Signature> {
        self.kp
            .sign_schnorr(Message::from_digest_slice(digest).unwrap())
    }

    async fn pubkey(&self) -> <Server as Origin>::Container<XOnlyPublicKey> {
        self.kp.x_only_public_key().0
    }
}

/// Stakechain wallet signer in-memory implementation.
#[derive(Debug)]
pub struct StakechainWalletSigner {
    /// [`Keypair`] for signing messages.
    kp: Keypair,
}

impl StakechainWalletSigner {
    /// Create a new operator with the given base xpriv.
    pub fn new(base: &Xpriv) -> Self {
        let xp = base
            .derive_priv(SECP256K1, &STAKECHAIN_WALLET_KEY_PATH)
            .expect("good child key");
        let kp = Keypair::from_secret_key(SECP256K1, &EvenSecretKey::from(xp.private_key));
        Self { kp }
    }
}

impl WalletSigner<Server> for StakechainWalletSigner {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Server as Origin>::Container<Signature> {
        self.kp
            .tap_tweak(SECP256K1, tweak)
            .to_keypair()
            .sign_schnorr(Message::from_digest_slice(digest).unwrap())
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Server as Origin>::Container<Signature> {
        self.kp
            .sign_schnorr(Message::from_digest_slice(digest).unwrap())
    }

    async fn pubkey(&self) -> <Server as Origin>::Container<XOnlyPublicKey> {
        self.kp.x_only_public_key().0
    }
}
