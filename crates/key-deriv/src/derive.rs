//! Core derivation functions for Strata Bridge keys.
//!
//! Provides opaque wrapper types for derived keys. These types can only be
//! constructed through derivation, ensuring they are valid by construction.
//! Each type implements [`Deref`] to provide access to the underlying data.
//!
//! # Usage
//!
//! ```rust,ignore
//! use strata_key_derivation::operator::OperatorKeys;
//! use strata_bridge_key_deriv::WalletKeys;
//!
//! let keys = OperatorKeys::new(&master_xpriv)?;
//! let wallet_keys = WalletKeys::derive(keys.base_xpriv())?;
//!
//! // Access the keypair via Deref
//! let pubkey = wallet_keys.general.x_only_public_key();
//! ```
//!
//! [`Deref`]: std::ops::Deref

use std::ops::Deref;

use bitcoin::{
    XOnlyPublicKey,
    bip32::{self, Xpriv},
    key::Keypair,
};
use secp256k1::SECP256K1;
use strata_bridge_primitives::secp::EvenSecretKey;

use crate::paths::{
    GENERAL_WALLET_KEY_PATH, MUSIG2_KEY_PATH, MUSIG2_NONCE_IKM_PATH, STAKECHAIN_PREIMG_IKM_PATH,
    STAKECHAIN_WALLET_KEY_PATH, WOTS_IKM_128_PATH, WOTS_IKM_256_PATH,
};

/// Error type for key derivation operations.
#[derive(Debug, thiserror::Error)]
pub enum DerivationError {
    /// BIP32 derivation failed.
    #[error("BIP32 derivation error: {0}")]
    Bip32(#[from] bip32::Error),
}

// =============================================================================
// Wallet Key Types
// =============================================================================

/// General wallet keypair for external funds management.
///
/// This type can only be constructed via [`WalletKeys::derive`].
/// Implements [`Deref<Target = Keypair>`] for access to signing methods.
#[derive(Debug)]
pub struct GeneralWalletKey(Keypair);

impl Deref for GeneralWalletKey {
    type Target = Keypair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Stakechain wallet keypair for stake operations.
///
/// This type can only be constructed via [`WalletKeys::derive`].
/// Implements [`Deref<Target = Keypair>`] for access to signing methods.
#[derive(Debug)]
pub struct StakechainWalletKey(Keypair);

impl Deref for StakechainWalletKey {
    type Target = Keypair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wallet keypairs for general and stakechain operations.
#[derive(Debug)]
pub struct WalletKeys {
    /// Keypair for the general wallet (external funds).
    pub general: GeneralWalletKey,
    /// Keypair for the stakechain wallet (reserved funds).
    pub stakechain: StakechainWalletKey,
}

impl WalletKeys {
    /// Derive wallet keys from the base xpriv.
    pub fn derive(base: &Xpriv) -> Result<Self, DerivationError> {
        let general_child = base.derive_priv(SECP256K1, &GENERAL_WALLET_KEY_PATH)?;
        let general = GeneralWalletKey(Keypair::from_secret_key(
            SECP256K1,
            &EvenSecretKey::from(general_child.private_key),
        ));

        let stakechain_child = base.derive_priv(SECP256K1, &STAKECHAIN_WALLET_KEY_PATH)?;
        let stakechain = StakechainWalletKey(Keypair::from_secret_key(
            SECP256K1,
            &EvenSecretKey::from(stakechain_child.private_key),
        ));

        Ok(Self {
            general,
            stakechain,
        })
    }

    /// Get the general wallet's x-only public key.
    pub fn general_pubkey(&self) -> XOnlyPublicKey {
        self.general.x_only_public_key().0
    }

    /// Get the stakechain wallet's x-only public key.
    pub fn stakechain_pubkey(&self) -> XOnlyPublicKey {
        self.stakechain.x_only_public_key().0
    }
}

// =============================================================================
// MuSig2 Key Types
// =============================================================================

/// MuSig2 signing keypair.
///
/// This type can only be constructed via [`Musig2Keys::derive`].
/// Implements [`Deref<Target = Keypair>`] for access to signing methods.
#[derive(Debug)]
pub struct Musig2Keypair(Keypair);

impl Deref for Musig2Keypair {
    type Target = Keypair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// MuSig2 nonce initial key material.
///
/// This type can only be constructed via [`Musig2Keys::derive`].
/// Implements [`Deref<Target = [u8; 32]>`] for access to the raw bytes.
#[derive(Debug)]
pub struct Musig2NonceIkm([u8; 32]);

impl Deref for Musig2NonceIkm {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// MuSig2 signing material.
#[derive(Debug)]
pub struct Musig2Keys {
    /// Keypair for MuSig2 threshold signing.
    pub keypair: Musig2Keypair,
    /// Initial key material for deterministic secnonce generation.
    pub nonce_ikm: Musig2NonceIkm,
}

impl Musig2Keys {
    /// Derive MuSig2 keys from the base xpriv.
    pub fn derive(base: &Xpriv) -> Result<Self, DerivationError> {
        let key_child = base.derive_priv(SECP256K1, &MUSIG2_KEY_PATH)?;
        let keypair = Musig2Keypair(Keypair::from_secret_key(
            SECP256K1,
            &EvenSecretKey::from(key_child.private_key),
        ));

        let nonce_child = base.derive_priv(SECP256K1, &MUSIG2_NONCE_IKM_PATH)?;
        let nonce_ikm = Musig2NonceIkm(nonce_child.private_key.secret_bytes());

        Ok(Self { keypair, nonce_ikm })
    }

    /// Get the MuSig2 x-only public key.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }
}

// =============================================================================
// WOTS Key Types
// =============================================================================

/// WOTS 128-bit initial key material.
///
/// This type can only be constructed via [`WotsIkm::derive`].
/// Implements [`Deref<Target = [u8; 32]>`] for access to the raw bytes.
#[derive(Debug)]
pub struct WotsIkm128([u8; 32]);

impl Deref for WotsIkm128 {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// WOTS 256-bit initial key material.
///
/// This type can only be constructed via [`WotsIkm::derive`].
/// Implements [`Deref<Target = [u8; 32]>`] for access to the raw bytes.
#[derive(Debug)]
pub struct WotsIkm256([u8; 32]);

impl Deref for WotsIkm256 {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// WOTS initial key material.
#[derive(Debug)]
pub struct WotsIkm {
    /// Initial key material for 128-bit WOTS keys.
    pub ikm_128: WotsIkm128,
    /// Initial key material for 256-bit WOTS keys.
    pub ikm_256: WotsIkm256,
}

impl WotsIkm {
    /// Derive WOTS initial key material from the base xpriv.
    pub fn derive(base: &Xpriv) -> Result<Self, DerivationError> {
        let ikm_128_child = base.derive_priv(SECP256K1, &WOTS_IKM_128_PATH)?;
        let ikm_128 = WotsIkm128(ikm_128_child.private_key.secret_bytes());

        let ikm_256_child = base.derive_priv(SECP256K1, &WOTS_IKM_256_PATH)?;
        let ikm_256 = WotsIkm256(ikm_256_child.private_key.secret_bytes());

        Ok(Self { ikm_128, ikm_256 })
    }
}

// =============================================================================
// Stakechain Preimage Types
// =============================================================================

/// Stakechain preimage initial key material.
///
/// This type can only be constructed via [`StakechainPreimageIkm::derive`].
/// Implements [`Deref<Target = [u8; 32]>`] for access to the raw bytes.
#[derive(Debug)]
pub struct StakechainPreimageIkm([u8; 32]);

impl Deref for StakechainPreimageIkm {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StakechainPreimageIkm {
    /// Derive stakechain preimage IKM from the base xpriv.
    pub fn derive(base: &Xpriv) -> Result<Self, DerivationError> {
        let child = base.derive_priv(SECP256K1, &STAKECHAIN_PREIMG_IKM_PATH)?;
        let ikm = child.private_key.secret_bytes();
        Ok(Self(ikm))
    }
}
