use std::future::Future;

use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    hashes::Hash,
    Txid,
};
use hkdf::Hkdf;
use make_buf::make_buf;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v1::traits::{Server, WotsSigner};
use sha2::Sha256;

/// A Winternitz One-Time Signature (WOTS) key generator seeded with some initial key material.
#[derive(Debug)]
pub struct SeededWotsSigner {
    /// Initial key material for 160-bit WOTS keys.
    ikm_160: [u8; 32],
    /// Initial key material for 256-bit WOTS keys.
    ikm_256: [u8; 32],
}

impl SeededWotsSigner {
    /// Creates a new WOTS signer from an operator's base private key (m/20000').
    pub fn new(base: &Xpriv) -> Self {
        Self {
            ikm_160: base
                .derive_priv(
                    SECP256K1,
                    &[
                        ChildNumber::from_hardened_idx(79).unwrap(),
                        ChildNumber::from_hardened_idx(160).unwrap(),
                        ChildNumber::from_hardened_idx(0).unwrap(),
                    ],
                )
                .unwrap()
                .private_key
                .secret_bytes(),
            ikm_256: base
                .derive_priv(
                    SECP256K1,
                    &[
                        ChildNumber::from_hardened_idx(79).unwrap(),
                        ChildNumber::from_hardened_idx(256).unwrap(),
                        ChildNumber::from_hardened_idx(0).unwrap(),
                    ],
                )
                .unwrap()
                .private_key
                .secret_bytes(),
        }
    }
}

impl WotsSigner<Server> for SeededWotsSigner {
    fn get_160_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = [u8; 20 * 160]> + Send {
        async move {
            let hk = Hkdf::<Sha256>::new(None, &self.ikm_160);
            let mut okm = [0u8; 20 * 160];
            let info = make_buf! {
                (txid.as_raw_hash().as_byte_array(), 32),
                (&vout.to_le_bytes(), 4),
                (&index.to_le_bytes(), 4),
            };
            hk.expand(&info, &mut okm).expect("valid output length");
            okm
        }
    }

    fn get_256_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> impl Future<Output = [u8; 20 * 256]> + Send {
        async move {
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
}
