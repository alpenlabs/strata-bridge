//! In-memory persistence for the Winternitz One-Time Signature (WOTS) keys.

use bitcoin::{
    bip32::Xpriv,
    hashes::{hash160, Hash},
    Txid,
};
use hkdf::Hkdf;
use make_buf::make_buf;
use musig2::secp256k1::SECP256K1;
use secret_service_proto::v1::traits::{Server, WotsSigner};
use sha2::Sha256;

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
    ) -> [u8; 20 * 36] {
        let hk = Hkdf::<Sha256>::new(None, &self.ikm_128);
        let mut okm = [0u8; 20 * 36];
        let info = make_buf! {
            (prestake_txid.as_raw_hash().as_byte_array(), 32),
            (&prestake_vout.to_le_bytes(), 4),
            (&index.to_le_bytes(), 4),
        };
        hk.expand(&info, &mut okm).expect("valid output length");
        okm
    }

    #[expect(refining_impl_trait)]
    async fn get_256_secret_key(&self, txid: Txid, vout: u32, index: u32) -> [u8; 20 * 68] {
        let hk = Hkdf::<Sha256>::new(None, &self.ikm_256);
        let mut okm = [0u8; 20 * 68];
        let info = make_buf! {
            (txid.as_raw_hash().as_byte_array(), 32),
            (&vout.to_le_bytes(), 4),
            (&index.to_le_bytes(), 4),
        };
        hk.expand(&info, &mut okm).expect("valid output length");
        okm
    }

    #[expect(refining_impl_trait)]
    async fn get_128_public_key(&self, txid: Txid, vout: u32, index: u32) -> [u8; 20 * 36] {
        let sk = self.get_128_secret_key(txid, vout, index).await;
        wots_public_key::<PS_HASH_TOTAL_LEN>(&PS_HASH, &sk)
    }

    #[expect(refining_impl_trait)]
    async fn get_256_public_key(&self, txid: Txid, vout: u32, index: u32) -> [u8; 20 * 68] {
        let sk = self.get_256_secret_key(txid, vout, index).await;
        wots_public_key::<PS_256_TOTAL_LEN>(&PS_256, &sk)
    }
}

/// Calculates ceil(log_base(n))
pub(super) const fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}

/// Contains the parameters to use with `Winternitz` struct
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct Parameters {
    /// Number of blocks of the actual message
    message_length: u32,
    /// Number of bits in one block
    block_length: u32,
    /// Number of blocks of the checksum part
    checksum_length: u32,
}

impl Parameters {
    /// Creates parameters with given message length (number of blocks in the message) and block
    /// length (number of bits in one block, in the closed range 4, 8)
    pub const fn new(message_block_count: u32, block_length: u32) -> Self {
        assert!(
            4 <= block_length && block_length <= 8,
            "You can only choose block lengths in the range [4, 8]"
        );
        Parameters {
            message_length: message_block_count,
            block_length,
            checksum_length: log_base_ceil(
                ((1 << block_length) - 1) * message_block_count,
                1 << block_length,
            ) + 1,
        }
    }

    /// Creates parameters with given message_length (number of bits in the message) and block
    /// length (number of bits in one block, in the closed range 4, 8)
    pub const fn new_by_bit_length(number_of_bits: u32, block_length: u32) -> Self {
        assert!(
            4 <= block_length && block_length <= 8,
            "You can only choose block lengths in the range [4, 8]"
        );
        let message_block_count = number_of_bits.div_ceil(block_length);
        Parameters {
            message_length: message_block_count,
            block_length,
            checksum_length: log_base_ceil(
                ((1 << block_length) - 1) * message_block_count,
                1 << block_length,
            ) + 1,
        }
    }

    /// Maximum value of a digit
    pub const fn d(&self) -> u32 {
        (1 << self.block_length) - 1
    }

    /// Number of bytes that can be represented at maximum with the parameters
    pub const fn byte_message_length(&self) -> u32 {
        (self.message_length * self.block_length + 7) / 8
    }

    /// Total number of blocks, i.e. sum of the number of blocks in the actual message and the
    /// checksum
    pub const fn total_length(&self) -> u32 {
        self.message_length + self.checksum_length
    }
}

/// Returns the public key for the given secret key and the parameters
fn wots_public_key<const N: usize>(ps: &Parameters, secret_key: &[u8; 20 * N]) -> [u8; 20 * N]
where
    [(); 20 * N + 1]:,
{
    let mut public_key = [0u8; 20 * N];
    for i in 0..ps.total_length() {
        let secret_i = {
            let mut buf = [0; 20 * N + 1];
            buf[..20 * N].copy_from_slice(secret_key);
            buf[20 * N] = i as u8;
            buf
        };
        let mut hash = hash160::Hash::hash(&secret_i);
        for _ in 0..ps.d() {
            hash = hash160::Hash::hash(&hash[..]);
        }

        let start = i as usize * 20;
        let end = start + 20;
        public_key[start..end].copy_from_slice(hash.as_byte_array());
    }
    public_key
}

const PS_256: Parameters = Parameters::new_by_bit_length(32 * 8, 4);
const PS_256_TOTAL_LEN: usize = PS_256.total_length() as usize;
const PS_HASH: Parameters = Parameters::new_by_bit_length(16 * 8, 4);
const PS_HASH_TOTAL_LEN: usize = PS_HASH.total_length() as usize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let sk: [u8; 20 * PS_HASH_TOTAL_LEN] = [0; 20 * PS_HASH_TOTAL_LEN];
        // thread_rng().fill(&mut sk);
        let pk = wots_public_key::<PS_HASH_TOTAL_LEN>(&PS_HASH, &sk);
        dbg!((sk, pk));
    }
}
