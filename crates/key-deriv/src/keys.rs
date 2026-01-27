use bitcoin::bip32::{ChildNumber, Xpriv};
use ed25519_dalek::SigningKey;
use secp256k1::SECP256K1;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    DerivationError,
    paths::{
        STRATA_BASE_IDX, STRATA_OPERATOR_BASE_DERIVATION_PATH,
        STRATA_OPERATOR_MESSAGE_DERIVATION_PATH,
    },
};

/// Operator keys derived from a master seed.
///
/// - Base key: `m/20000'/20'`
/// - Message signing key: `m/20000'/20'/100'`
#[derive(Debug, Clone)]
pub struct OperatorKeys {
    /// Operator's base [`Xpriv`].
    ///
    /// # Notes
    ///
    /// This is the [`Xpriv`] at `m/20000'/20'`, generated from only hardened paths.
    base: Xpriv,

    /// Operator's message signing ed25519 key.
    message: SigningKey,
}

impl OperatorKeys {
    /// Creates a new [`OperatorKeys`] from a master [`Xpriv`].
    pub fn new(master: &Xpriv) -> Result<Self, DerivationError> {
        let base_xpriv = master.derive_priv(SECP256K1, &STRATA_BASE_IDX)?;
        let operator_xpriv =
            base_xpriv.derive_priv(SECP256K1, &STRATA_OPERATOR_BASE_DERIVATION_PATH)?;
        let message_xpriv =
            operator_xpriv.derive_priv(SECP256K1, &STRATA_OPERATOR_MESSAGE_DERIVATION_PATH)?;

        // Derive ed25519 signing key from the BIP-32 derived secret
        let message = SigningKey::from_bytes(&message_xpriv.private_key.secret_bytes());

        Ok(Self {
            base: operator_xpriv,
            message,
        })
    }

    /// Operator's base [`Xpriv`].
    ///
    /// # Notes
    ///
    /// This is the [`Xpriv`] at `m/20000'/20'`, derived from the master [`Xpriv`].
    pub const fn base_xpriv(&self) -> &Xpriv {
        &self.base
    }

    /// Operator's message signing ed25519 key at `m/20000'/20'/100'`.
    pub const fn message_signing_key(&self) -> &SigningKey {
        &self.message
    }
}

// Manual Drop implementation to zeroize keys on drop.
impl Drop for OperatorKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for OperatorKeys {
    #[inline]
    fn zeroize(&mut self) {
        let Self { base, message } = self;

        // # Security note
        //
        // Going over all possible "zeroizable" fields.
        // What we cannot zeroize is only:
        //
        // - Network: enum
        //
        // These are fine to leave as they are since they are public parameters,
        // and not secret values.
        //
        // NOTE: `Xpriv.private_key` (`SecretKey`) `non_secure_erase` writes `1`s to the memory.

        // Zeroize base components
        base.depth.zeroize();
        {
            let fingerprint: &mut [u8; 4] = base.parent_fingerprint.as_mut();
            fingerprint.zeroize();
        }
        base.private_key.non_secure_erase();
        {
            let chaincode: &mut [u8; 32] = base.chain_code.as_mut();
            chaincode.zeroize();
        }
        let raw_ptr = &mut base.child_number as *mut ChildNumber;
        // SAFETY: `base.child_number` is a valid enum variant
        //          and will not be accessed after zeroization.
        //          Also there are only two possible variants that will
        //          always have an `index` which is a `u32`.
        //          Note that `ChildNumber` does not have the `#[non_exhaustive]`
        //          attribute.
        unsafe {
            *raw_ptr = if base.child_number.is_normal() {
                ChildNumber::Normal { index: 0 }
            } else {
                ChildNumber::Hardened { index: 0 }
            };
        }

        // Zeroize ed25519 signing key by replacing with a zeroed key.
        // This drops the old key, triggering ZeroizeOnDrop.
        *message = SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl ZeroizeOnDrop for OperatorKeys {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_zeroize() {
        use bitcoin::Network;

        let master = Xpriv::new_master(Network::Regtest, &[2u8; 32]).unwrap();
        let mut keys = OperatorKeys::new(&master).unwrap();

        // Store original values
        let base_chaincode = *keys.base_xpriv().chain_code.as_bytes();
        let message_key_bytes = keys.message_signing_key().to_bytes();

        // Verify data exists
        assert_ne!(base_chaincode, [0u8; 32]);
        assert_ne!(message_key_bytes, [0u8; 32]);

        // Manually zeroize
        keys.zeroize();

        // Verify fields are zeroed
        // NOTE: SecretKey::non_secure_erase writes `1`s to the memory.
        assert_eq!(keys.base_xpriv().private_key.secret_bytes(), [1u8; 32]);
        assert_eq!(keys.message_signing_key().to_bytes(), [0u8; 32]);
        assert_eq!(*keys.base_xpriv().chain_code.as_bytes(), [0u8; 32]);
        assert_eq!(*keys.base_xpriv().parent_fingerprint.as_bytes(), [0u8; 4]);
        assert_eq!(keys.base_xpriv().depth, 0);

        // Check if child numbers are zeroed while maintaining their hardened/normal status
        match keys.base_xpriv().child_number {
            ChildNumber::Normal { index } => assert_eq!(index, 0),
            ChildNumber::Hardened { index } => assert_eq!(index, 0),
        }
    }
}
