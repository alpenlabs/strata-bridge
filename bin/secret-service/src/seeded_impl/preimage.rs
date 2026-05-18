//! In-memory persistence for preimages.

use bitcoin::{bip32::Xpriv, hashes::Hash, Txid};
use hkdf::Hkdf;
use make_buf::make_buf;
use secret_service_proto::v2::traits::{Preimages, Server};
use sha2::Sha256;
use strata_bridge_key_deriv::PreimageIkm;

/// Secret data for the preimages.
#[derive(Debug)]
pub struct Preimg {
    /// The initial key material to derive preimages.
    ikm: PreimageIkm,
}

impl Preimg {
    /// Creates a new [`Preimg`] given a master [`Xpriv`].
    pub fn new(base: &Xpriv) -> Self {
        let preimage_ikm = PreimageIkm::derive(base).expect("valid preimage ikm");
        Self { ikm: preimage_ikm }
    }
}

impl Preimages<Server> for Preimg {
    /// Gets a preimage given a pre-stake transaction ID, and output index; and
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
