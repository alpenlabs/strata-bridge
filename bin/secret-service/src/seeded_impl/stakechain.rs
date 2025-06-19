//! In-memory persistence for Stake Chain preimages.

use bitcoin::{bip32::Xpriv, hashes::Hash, Txid};
use hkdf::Hkdf;
use make_buf::make_buf;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v2::traits::{Server, StakeChainPreimages};
use sha2::Sha256;

use super::paths::STAKECHAIN_PREIMG_IKM_PATH;

/// Secret data for the Stake Chain preimages.
#[derive(Debug)]
pub struct StakeChain {
    /// The initial key material to derive Stake Chain preimages.
    ikm: [u8; 32],
}

impl StakeChain {
    /// Creates a new [`StakeChain`] given a master [`Xpriv`].
    pub fn new(base: &Xpriv) -> Self {
        let xpriv = base
            .derive_priv(SECP256K1, &STAKECHAIN_PREIMG_IKM_PATH)
            .expect("good child key");
        Self {
            ikm: xpriv.private_key.secret_bytes(),
        }
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
        let hk = Hkdf::<Sha256>::new(None, &self.ikm);
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
