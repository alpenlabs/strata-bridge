//! In-memory persistence for the Winternitz One-Time Signature (WOTS) keys.

use bitcoin::{bip32::Xpriv, hashes::Hash, Txid};
use hkdf::Hkdf;
use make_buf::make_buf;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v1::traits::{Server, WotsSigner};
use sha2::Sha256;

use super::paths::{WOTS_IKM_128_PATH, WOTS_IKM_256_PATH};

/// A Winternitz One-Time Signature (WOTS) key generator seeded with some initial key material.
#[derive(Debug)]
pub struct SeededWotsSigner {
    /// Initial key material for 128-bit WOTS keys.
    ikm_128: [u8; 32],
    /// Initial key material for 256-bit WOTS keys.
    ikm_256: [u8; 32],
}

impl SeededWotsSigner {
    /// Creates a new WOTS signer from an operator's base private key (m/20000').
    pub fn new(base: &Xpriv) -> Self {
        Self {
            ikm_128: base
                .derive_priv(SECP256K1, &WOTS_IKM_128_PATH)
                .unwrap()
                .private_key
                .secret_bytes(),
            ikm_256: base
                .derive_priv(SECP256K1, &WOTS_IKM_256_PATH)
                .unwrap()
                .private_key
                .secret_bytes(),
        }
    }
}

impl WotsSigner<Server> for SeededWotsSigner {
    async fn get_128_key(&self, txid: Txid, vout: u32, index: u32) -> [u8; 20 * 128] {
        let hk = Hkdf::<Sha256>::new(None, &self.ikm_128);
        let mut okm = [0u8; 20 * 128];
        let info = make_buf! {
            (txid.as_raw_hash().as_byte_array(), 32),
            (&vout.to_le_bytes(), 4),
            (&index.to_le_bytes(), 4),
        };
        hk.expand(&info, &mut okm).expect("valid output length");
        okm
    }

    async fn get_256_key(&self, txid: Txid, vout: u32, index: u32) -> [u8; 20 * 256] {
        let hk = Hkdf::<Sha256>::new(None, &self.ikm_256);
        let mut okm = [0u8; 20 * 256];
        let info = make_buf! {
            (txid.as_raw_hash().as_byte_array(), 32),
            (&vout.to_le_bytes(), 4),
            (&index.to_le_bytes(), 4),
        };
        hk.expand(&info, &mut okm).expect("valid output length");
        okm
    }
}
