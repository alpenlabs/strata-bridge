//! BIP-328 aggregate-key derivation.

use bitcoin::bip32::{ChildNumber, Xpub};
use musig2::secp::{MaybeScalar, Scalar};
use secp256k1::{PublicKey, SECP256K1};

/// Fixed chain code for BIP-328 aggregate public key derivation.
const BIP328_CHAIN_CODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xca, 0x02, 0xa6, 0xf9, 0x74, 0xc4, 0x59, 0x89, 0x24, 0xc3, 0x6b, 0x57, 0x76,
    0x2d, 0x32, 0xcb, 0x45, 0x71, 0x71, 0x67, 0xe3, 0x00, 0x62, 0x2c, 0x71, 0x67, 0xe3, 0x89, 0x65,
];

/// Derives the BIP-328 `/0/0` child of the given aggregate public key.
///
/// This function returns the public key of the resulting `/0/0` child,
/// as well as the tweak that leads from the aggregate public key to the child.
pub fn derive_musig_0_0(
    aggregate_pubkey: PublicKey,
) -> Result<(PublicKey, MaybeScalar), bitcoin::bip32::Error> {
    let child_number = ChildNumber::Normal { index: 0 };
    let mut xpub = Xpub {
        network: bitcoin::NetworkKind::Main,
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number,
        public_key: aggregate_pubkey,
        chain_code: BIP328_CHAIN_CODE.into(),
    };
    let tweak1 = Scalar::from(xpub.ckd_pub_tweak(child_number)?.0);
    xpub = xpub.ckd_pub(SECP256K1, child_number)?;
    let tweak2 = Scalar::from(xpub.ckd_pub_tweak(child_number)?.0);
    xpub = xpub.ckd_pub(SECP256K1, child_number)?;
    Ok((xpub.public_key, tweak1 + tweak2))
}
