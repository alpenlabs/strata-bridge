//! In-memory persistence for preimages.

use bitcoin::{bip32::Xpriv, Txid};
use secret_service_proto::v2::traits::{Preimages, Server};
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
        self.ikm
            .derive_preimage(prestake_txid, prestake_vout, stake_index)
    }
}
