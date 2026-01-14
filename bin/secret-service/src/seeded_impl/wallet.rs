//! In-memory persistence for operator's secret data.

use bitcoin::{bip32::Xpriv, key::TapTweak, TapNodeHash, XOnlyPublicKey};
use musig2::secp256k1::{schnorr::Signature, Message, SECP256K1};
use secret_service_proto::v2::traits::{Origin, SchnorrSigner, Server};
use strata_bridge_key_deriv::{GeneralWalletKey, StakechainWalletKey, WalletKeys};

/// General wallet signer in-memory implementation.
#[derive(Debug)]
pub struct GeneralWalletSigner {
    /// Keypair for signing messages.
    kp: GeneralWalletKey,
}

impl GeneralWalletSigner {
    /// Create a new operator with the given base xpriv.
    pub fn new(base: &Xpriv) -> Self {
        let wallet_keys = WalletKeys::derive(base).expect("valid wallet keys");
        Self {
            kp: wallet_keys.general,
        }
    }
}

impl SchnorrSigner<Server> for GeneralWalletSigner {
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
    /// Keypair for signing messages.
    kp: StakechainWalletKey,
}

impl StakechainWalletSigner {
    /// Create a new operator with the given base xpriv.
    pub fn new(base: &Xpriv) -> Self {
        let wallet_keys = WalletKeys::derive(base).expect("valid wallet keys");
        Self {
            kp: wallet_keys.stakechain,
        }
    }
}

impl SchnorrSigner<Server> for StakechainWalletSigner {
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
