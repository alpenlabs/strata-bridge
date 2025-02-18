use std::future::Future;

use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    hashes::Hash,
    Txid,
};
use hkdf::Hkdf;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v1::traits::{Server, WotsSigner};
use sha2::Sha256;

pub struct SeededWotsSigner {
    ikm_160: [u8; 32],
    ikm_256: [u8; 32],
}

impl SeededWotsSigner {
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
        index: u32,
        vout: u32,
        txid: Txid,
    ) -> impl Future<Output = [u8; 20 * 160]> + Send {
        async move {
            let hk = Hkdf::<Sha256>::new(None, &self.ikm_160);
            let mut okm = [0u8; 20 * 160];
            let info = {
                let mut buf = [0; 40];
                buf[..32].copy_from_slice(txid.as_raw_hash().as_byte_array());
                buf[32..36].copy_from_slice(&vout.to_le_bytes());
                buf[36..].copy_from_slice(&index.to_le_bytes());
                buf
            };
            hk.expand(&info, &mut okm).expect("valid output length");
            okm
        }
    }

    fn get_256_key(
        &self,
        index: u32,
        vout: u32,
        txid: Txid,
    ) -> impl Future<Output = [u8; 20 * 256]> + Send {
        async move {
            let hk = Hkdf::<Sha256>::new(None, &self.ikm_256);
            let mut okm = [0u8; 20 * 256];
            let info = {
                let mut buf = [0; 40];
                buf[..32].copy_from_slice(txid.as_raw_hash().as_byte_array());
                buf[32..36].copy_from_slice(&vout.to_le_bytes());
                buf[36..].copy_from_slice(&index.to_le_bytes());
                buf
            };
            hk.expand(&info, &mut okm).expect("valid output length");
            okm
        }
    }
}
