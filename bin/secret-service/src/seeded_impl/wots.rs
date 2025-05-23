//! In-memory persistence for the Winternitz One-Time Signature (WOTS) keys.

use bitcoin::{bip32::Xpriv, hashes::Hash, Txid};
use bitvm::signatures::wots_api::{wots256, wots_hash};
use hkdf::Hkdf;
use make_buf::make_buf;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v1::traits::{Server, WotsSigner};
use sha2::Sha256;
use wots::{
    key_width, wots_public_key, wots_sign_128_bitvm, wots_sign_256_bitvm, PARAMS_128,
    PARAMS_128_TOTAL_LEN, PARAMS_256, PARAMS_256_TOTAL_LEN, WINTERNITZ_DIGIT_WIDTH,
};

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
    #[expect(refining_impl_trait)]
    async fn get_128_secret_key(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        index: u32,
    ) -> [u8; 20 * key_width(128, WINTERNITZ_DIGIT_WIDTH)] {
        let hk = Hkdf::<Sha256>::new(None, &self.ikm_128);
        let mut okm = [0u8; 20 * key_width(128, WINTERNITZ_DIGIT_WIDTH)];
        let info = make_buf! {
            (prestake_txid.as_raw_hash().as_byte_array(), 32),
            (&prestake_vout.to_le_bytes(), 4),
            (&index.to_le_bytes(), 4),
        };
        hk.expand(&info, &mut okm).expect("valid output length");
        okm
    }

    #[expect(refining_impl_trait)]
    async fn get_256_secret_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> [u8; 20 * key_width(256, WINTERNITZ_DIGIT_WIDTH)] {
        let hk = Hkdf::<Sha256>::new(None, &self.ikm_256);
        let mut okm = [0u8; 20 * key_width(256, WINTERNITZ_DIGIT_WIDTH)];
        let info = make_buf! {
            (txid.as_raw_hash().as_byte_array(), 32),
            (&vout.to_le_bytes(), 4),
            (&index.to_le_bytes(), 4),
        };
        hk.expand(&info, &mut okm).expect("valid output length");
        okm
    }

    #[expect(refining_impl_trait)]
    async fn get_128_public_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> [u8; 20 * key_width(128, WINTERNITZ_DIGIT_WIDTH)] {
        let sk = self.get_128_secret_key(txid, vout, index).await;
        wots_public_key::<PARAMS_128_TOTAL_LEN>(&PARAMS_128, &sk)
    }

    #[expect(refining_impl_trait)]
    async fn get_256_public_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> [u8; 20 * key_width(256, WINTERNITZ_DIGIT_WIDTH)] {
        let sk = self.get_256_secret_key(txid, vout, index).await;
        wots_public_key::<PARAMS_256_TOTAL_LEN>(&PARAMS_256, &sk)
    }

    async fn get_128_signature(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
        msg: &[u8; 16],
    ) -> wots_hash::Signature {
        let sk = self.get_128_secret_key(txid, vout, index).await;
        wots_sign_128_bitvm(msg, &sk)
    }

    async fn get_256_signature(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
        msg: &[u8; 32],
    ) -> wots256::Signature {
        let sk = self.get_256_secret_key(txid, vout, index).await;
        wots_sign_256_bitvm(msg, &sk)
    }
}
