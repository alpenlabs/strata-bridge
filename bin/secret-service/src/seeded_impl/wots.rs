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
        wots_public_key::<PARAMS_HASH_TOTAL_LEN>(&PARAMS_HASH, &sk)
    }

    #[expect(refining_impl_trait)]
    async fn get_256_public_key(&self, txid: Txid, vout: u32, index: u32) -> [u8; 20 * 68] {
        let sk = self.get_256_secret_key(txid, vout, index).await;
        wots_public_key::<PARAMS_256_TOTAL_LEN>(&PARAMS_256, &sk)
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

// Taken from BitVM pile of amazing code.
const PARAMS_256: Parameters = Parameters::new_by_bit_length(32 * 8, 4);
const PARAMS_256_TOTAL_LEN: usize = PARAMS_256.total_length() as usize;
const PARAMS_HASH: Parameters = Parameters::new_by_bit_length(16 * 8, 4);
const PARAMS_HASH_TOTAL_LEN: usize = PARAMS_HASH.total_length() as usize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let sk: [u8; 20 * PARAMS_HASH_TOTAL_LEN] = [0; 20 * PARAMS_HASH_TOTAL_LEN];
        let pk = wots_public_key::<PARAMS_HASH_TOTAL_LEN>(&PARAMS_HASH, &sk);
        // This matches with the current BitVM implementation (as of 2025-03-30).
        let expected = [
            231, 105, 12, 202, 16, 103, 212, 67, 88, 20, 155, 195, 135, 65, 116, 73, 91, 255, 27,
            70, 30, 116, 139, 34, 50, 125, 124, 82, 60, 40, 216, 178, 154, 2, 48, 249, 4, 243, 84,
            111, 38, 171, 180, 122, 186, 199, 172, 99, 135, 191, 255, 174, 165, 114, 161, 255, 198,
            160, 84, 82, 188, 128, 134, 40, 192, 171, 90, 216, 178, 246, 213, 201, 74, 232, 167,
            100, 226, 134, 51, 181, 151, 30, 201, 192, 23, 94, 122, 102, 16, 224, 193, 187, 190,
            148, 27, 31, 206, 56, 85, 76, 41, 133, 232, 56, 23, 75, 122, 182, 65, 33, 134, 224, 87,
            202, 253, 200, 41, 121, 228, 233, 145, 217, 217, 187, 157, 45, 162, 72, 178, 193, 70,
            22, 243, 100, 112, 11, 163, 37, 217, 59, 160, 87, 112, 183, 16, 200, 64, 125, 94, 64,
            73, 245, 40, 95, 253, 38, 194, 158, 179, 23, 53, 191, 54, 192, 95, 238, 216, 169, 63,
            215, 3, 105, 199, 124, 244, 138, 146, 178, 235, 115, 65, 204, 163, 129, 254, 159, 62,
            105, 176, 218, 164, 253, 163, 220, 103, 199, 152, 99, 83, 190, 214, 135, 68, 99, 21,
            80, 86, 229, 210, 241, 70, 161, 131, 164, 214, 78, 187, 222, 68, 14, 27, 207, 75, 80,
            2, 158, 77, 73, 83, 251, 78, 247, 242, 35, 134, 22, 137, 242, 225, 191, 24, 182, 175,
            138, 218, 215, 102, 178, 164, 206, 52, 195, 138, 61, 135, 128, 222, 248, 107, 75, 216,
            132, 8, 46, 86, 233, 2, 108, 116, 204, 196, 114, 208, 58, 163, 248, 216, 2, 185, 249,
            247, 191, 28, 2, 5, 222, 27, 81, 32, 88, 204, 91, 36, 154, 125, 187, 78, 43, 114, 162,
            239, 213, 93, 117, 118, 235, 104, 183, 81, 7, 221, 78, 58, 195, 218, 209, 104, 30, 220,
            107, 127, 81, 100, 205, 103, 110, 240, 113, 11, 79, 14, 232, 188, 20, 82, 91, 103, 212,
            134, 56, 1, 73, 107, 173, 126, 105, 143, 51, 2, 110, 160, 85, 111, 180, 251, 222, 174,
            164, 76, 3, 234, 201, 131, 149, 186, 183, 91, 127, 174, 159, 249, 160, 97, 160, 241,
            41, 242, 83, 79, 132, 76, 77, 59, 22, 21, 111, 59, 23, 206, 154, 48, 236, 157, 92, 117,
            175, 235, 141, 42, 131, 50, 252, 122, 149, 177, 186, 226, 181, 186, 151, 57, 231, 119,
            21, 212, 51, 252, 71, 187, 100, 182, 242, 39, 245, 19, 67, 66, 198, 226, 215, 242, 190,
            210, 205, 56, 183, 161, 112, 76, 175, 146, 74, 219, 80, 205, 129, 197, 237, 162, 33,
            112, 41, 56, 63, 247, 71, 6, 77, 43, 203, 80, 173, 44, 55, 220, 27, 25, 171, 253, 191,
            191, 91, 130, 88, 49, 192, 186, 234, 205, 25, 242, 25, 219, 74, 157, 84, 249, 148, 243,
            72, 8, 132, 133, 210, 234, 40, 43, 236, 178, 127, 144, 93, 27, 128, 25, 34, 2, 246,
            158, 53, 255, 103, 119, 137, 48, 95, 22, 205, 111, 179, 92, 21, 119, 12, 215, 101, 71,
            21, 85, 87, 152, 68, 129, 80, 222, 165, 200, 109, 23, 167, 142, 252, 173, 109, 217,
            252, 169, 2, 190, 4, 108, 173, 42, 206, 204, 144, 159, 46, 4, 179, 101, 26, 179, 138,
            53, 210, 170, 169, 43, 90, 199, 212, 106, 244, 103, 238, 9, 172, 83, 125, 104, 171,
            194, 173, 103, 175, 113, 235, 140, 93, 51, 136, 100, 10, 152, 111, 119, 100, 144, 23,
            130, 60, 97, 192, 216, 43, 68, 41, 251, 34, 157, 247, 81, 228, 175, 12, 83, 240, 212,
            98, 189, 245, 228, 206, 114, 44, 132, 190, 53, 15, 26, 49, 87, 50, 17, 202, 213, 91,
            203, 52, 47, 31, 148, 48, 49, 47, 36, 141, 58, 54, 247, 171, 181, 23, 68, 225, 48, 52,
            149, 92, 10, 18, 199, 117, 249, 247, 248, 144, 244, 208, 100, 38, 27, 22, 176, 116, 62,
            2, 46, 127, 164, 207, 179, 197, 19, 18, 156, 30, 170, 66, 6, 159, 137, 29, 69, 244,
            205, 179, 57, 98, 140, 103, 223, 130, 198, 212, 248, 98, 203, 134, 208, 142, 144, 2,
            14, 234, 153, 15, 134, 178,
        ];
        assert_eq!(pk, expected);
    }
}
