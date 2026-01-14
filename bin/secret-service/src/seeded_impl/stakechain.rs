//! In-memory persistence for Stake Chain preimages.

use bitcoin::{bip32::Xpriv, hashes::Hash, Txid};
use hkdf::Hkdf;
use make_buf::make_buf;
use secret_service_proto::v2::traits::{Server, StakeChainPreimages};
use sha2::Sha256;
use strata_bridge_key_deriv::StakechainPreimageIkm;

/// Secret data for the Stake Chain preimages.
#[derive(Debug)]
pub struct StakeChain {
    /// The initial key material to derive Stake Chain preimages.
    ikm: StakechainPreimageIkm,
}

impl StakeChain {
    /// Creates a new [`StakeChain`] given a master [`Xpriv`].
    pub fn new(base: &Xpriv) -> Self {
        let preimage_ikm = StakechainPreimageIkm::derive(base).expect("valid preimage ikm");
        Self { ikm: preimage_ikm }
    }
}

impl StakeChainPreimages<Server> for StakeChain {
    /// Gets a preimage for a Stake Chain, given a pre-stake transaction ID, and output index; and
    /// stake index.
    async fn get_preimg(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &*self.ikm);
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
