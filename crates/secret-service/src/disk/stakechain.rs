use std::future::Future;

use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    hashes::Hash,
    Txid,
};
use hkdf::Hkdf;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v1::traits::{Server, StakeChainPreimages};
use sha2::Sha256;

pub struct StakeChain {
    ikm: [u8; 32],
}

impl StakeChain {
    pub fn new(base: &Xpriv) -> Self {
        let xpriv = base
            .derive_priv(
                SECP256K1,
                &[
                    ChildNumber::from_hardened_idx(80).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                ],
            )
            .expect("good child key");
        Self {
            ikm: xpriv.private_key.secret_bytes(),
        }
    }
}

impl StakeChainPreimages<Server> for StakeChain {
    fn get_preimg(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> impl Future<Output = [u8; 32]> + Send {
        async move {
            let hk = Hkdf::<Sha256>::new(None, &self.ikm);
            let mut okm = [0u8; 32];
            let info = {
                let mut buf = [0; 40];
                buf[..32].copy_from_slice(&prestake_txid.as_raw_hash().to_byte_array());
                buf[32..36].copy_from_slice(&prestake_vout.to_le_bytes());
                buf[36..].copy_from_slice(&stake_index.to_le_bytes());
                buf
            };
            hk.expand(&info, &mut okm)
                .expect("32 is a valid length for Sha256 to output");
            okm
        }
    }
}
