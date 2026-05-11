//! Core derivation functions for Strata Bridge keys.
//!
//! Provides opaque wrapper types for derived keys. These types can only be
//! constructed through derivation, ensuring they are valid by construction.
//! Each type implements [`Deref`] to provide access to the underlying data.
//!
//! # Usage
//!
//! ```rust,ignore
//! use strata_bridge_key_deriv::{OperatorKeys, WalletKeys};
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
    Txid, XOnlyPublicKey,
    bip32::{self, Xpriv},
    hashes::Hash,
    key::Keypair,
};
use hkdf::Hkdf;
use make_buf::make_buf;
use secp256k1::SECP256K1;
use sha2::Sha256;
use strata_bridge_primitives::secp::EvenSecretKey;

use crate::paths::{
    GENERAL_WALLET_KEY_PATH, MUSIG2_KEY_PATH, MUSIG2_NONCE_IKM_PATH, PREIMG_IKM_PATH,
    RESERVED_WALLET_KEY_PATH, WOTS_IKM_128_PATH, WOTS_IKM_256_PATH,
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

/// Reserved wallet keypair for operations that require reserving UTXOs long-term.
///
/// This type can only be constructed via [`WalletKeys::derive`].
/// Implements [`Deref<Target = Keypair>`] for access to signing methods.
#[derive(Debug)]
pub struct ReservedWalletKey(Keypair);

impl Deref for ReservedWalletKey {
    type Target = Keypair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wallet keypairs for general and reserved operations.
#[derive(Debug)]
pub struct WalletKeys {
    /// Keypair for the general wallet (external funds).
    pub general: GeneralWalletKey,
    /// Keypair for the reserved wallet (reserved funds).
    pub reserved: ReservedWalletKey,
}

impl WalletKeys {
    /// Derive wallet keys from the base xpriv.
    pub fn derive(base: &Xpriv) -> Result<Self, DerivationError> {
        let general_child = base.derive_priv(SECP256K1, &GENERAL_WALLET_KEY_PATH)?;
        let general = GeneralWalletKey(Keypair::from_secret_key(
            SECP256K1,
            &EvenSecretKey::from(general_child.private_key),
        ));

        let reserved_child = base.derive_priv(SECP256K1, &RESERVED_WALLET_KEY_PATH)?;
        let reserved = ReservedWalletKey(Keypair::from_secret_key(
            SECP256K1,
            &EvenSecretKey::from(reserved_child.private_key),
        ));

        Ok(Self { general, reserved })
    }

    /// Get the general wallet's x-only public key.
    pub fn general_pubkey(&self) -> XOnlyPublicKey {
        self.general.x_only_public_key().0
    }

    /// Get the reserved wallet's x-only public key.
    pub fn reserved_pubkey(&self) -> XOnlyPublicKey {
        self.reserved.x_only_public_key().0
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
// Preimage Types
// =============================================================================

/// Preimage initial key material.
///
/// This type can only be constructed via [`PreimageIkm::derive`].
/// Implements [`Deref<Target = [u8; 32]>`] for access to the raw bytes.
#[derive(Debug)]
pub struct PreimageIkm([u8; 32]);

impl Deref for PreimageIkm {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PreimageIkm {
    /// Derive preimage IKM from the base xpriv.
    pub fn derive(base: &Xpriv) -> Result<Self, DerivationError> {
        let child = base.derive_priv(SECP256K1, &PREIMG_IKM_PATH)?;
        let ikm = child.private_key.secret_bytes();
        Ok(Self(ikm))
    }

    /// Derive the deterministic stakechain preimage for a stake funding outpoint.
    pub fn derive_preimage(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; 32];
        let info = make_buf! {
            (prestake_txid.as_raw_hash().as_byte_array(), 32),
            (&prestake_vout.to_le_bytes(), 4),
            (&stake_index.to_le_bytes(), 4)
        };
        hk.expand(&info, &mut okm)
            .expect("32 is a valid length for Sha256 to output");
        okm
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Txid, hashes::Hash};

    use super::PreimageIkm;

    #[test]
    fn stakechain_preimage_derivation_is_deterministic() {
        let ikm = PreimageIkm([1; 32]);
        let txid = Txid::from_byte_array([2; 32]);

        let first = ikm.derive_preimage(txid, 3, 0);
        let second = ikm.derive_preimage(txid, 3, 0);

        assert_eq!(
            first, second,
            "preimage derivation must be deterministic for the same stake funding outpoint"
        );
    }

    #[test]
    fn stakechain_preimage_derivation_binds_to_funding_outpoint() {
        let ikm = PreimageIkm([1; 32]);
        let txid = Txid::from_byte_array([2; 32]);

        let base = ikm.derive_preimage(txid, 3, 0);
        let different_vout = ikm.derive_preimage(txid, 4, 0);
        let different_stake_index = ikm.derive_preimage(txid, 3, 1);

        assert_ne!(
            base, different_vout,
            "changing the stake funding vout must change the derived preimage"
        );
        assert_ne!(
            base, different_stake_index,
            "changing the stake index must change the derived preimage"
        );
    }
}
