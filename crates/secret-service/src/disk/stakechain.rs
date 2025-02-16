use std::future::Future;

use hkdf::Hkdf;
use secret_service_proto::v1::traits::{Server, StakeChainPreimages};
use sha2::Sha256;

pub struct StakeChain {
    seed: [u8; 32],
}

impl StakeChain {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl StakeChainPreimages<Server> for StakeChain {
    fn get_preimg(&self, deposit_index: u64) -> impl Future<Output = [u8; 32]> + Send {
        async move {
            let hk = Hkdf::<Sha256>::new(Some(&deposit_index.to_le_bytes()), &self.seed);
            let mut okm = [0u8; 32];
            hk.expand(b"strata-bridge-stakechain", &mut okm)
                .expect("32 is a valid length for Sha256 to output");
            okm
        }
    }
}
