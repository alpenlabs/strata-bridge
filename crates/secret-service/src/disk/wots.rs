use std::future::Future;

use bitcoin::{hashes::Hash, Txid};
use hkdf::Hkdf;
use secret_service_proto::v1::traits::{Server, WotsSigner};
use sha2::Sha256;

pub struct SeededWotsSigner {
    seed: [u8; 32],
}

impl SeededWotsSigner {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl WotsSigner<Server> for SeededWotsSigner {
    fn get_key(&self, index: u64, txid: Txid) -> impl Future<Output = [u8; 64]> + Send {
        async move {
            let salt = {
                let mut buf = [0; 32 + size_of::<u64>()];
                buf[..32].copy_from_slice(txid.as_raw_hash().as_byte_array());
                buf[32..].copy_from_slice(&index.to_le_bytes());
                buf
            };
            let hk = Hkdf::<Sha256>::new(Some(&salt), &self.seed);
            let mut okm = [0u8; 64];
            hk.expand(b"strata-bridge-winternitz", &mut okm)
                .expect("64 is a valid length for Sha256 to output");
            okm
        }
    }
}
