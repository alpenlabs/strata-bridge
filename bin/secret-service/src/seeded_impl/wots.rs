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

// Changing this number may cause certain code to break as the signing code is not designed to
// handle cases where the digit width doesn't divide byte width without residue.
const WINTERNITZ_DIGIT_WIDTH: usize = 4;
const WINTERNITZ_MAX_DIGIT: usize = (2 << WINTERNITZ_DIGIT_WIDTH) - 1;

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

/// Calculates the total WOTS key width based off of the number of bits in the message being signed
/// and the number of bits per WOTS digit.
const fn key_width(num_bits: usize, digit_width: usize) -> usize {
    let num_digits = num_bits.div_ceil(digit_width);
    num_digits + checksum_width(num_bits, digit_width)
}

/// Calculates the total WOTS key digits used for the checksum.
const fn checksum_width(num_bits: usize, digit_width: usize) -> usize {
    let num_digits = num_bits.div_ceil(digit_width);
    let max_digit = (2 << digit_width) - 1;
    let max_checksum = num_digits * max_digit;
    let checksum_bytes = log_base_ceil(max_checksum as u32, 256) as usize;
    (checksum_bytes * 8).div_ceil(digit_width)
}

/// Contains the parameters to use with `Winternitz` struct
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct Parameters {
    /// Number of digits of the actual message
    message_length: u32,
    /// Number of bits in one digit
    digit_width: u32,
    /// Number of digits of the checksum part
    checksum_length: u32,
}

impl Parameters {
    /// Creates parameters with given message length (number of digits in the message) and digit
    /// length (number of bits in one digit, in the closed range 4, 8)
    pub const fn new(message_num_digits: u32, digit_width: u32) -> Self {
        assert!(
            4 <= digit_width && digit_width <= 8,
            "You can only choose digit widths in the range [4, 8]"
        );
        Parameters {
            message_length: message_num_digits,
            digit_width,
            checksum_length: log_base_ceil(
                ((1 << digit_width) - 1) * message_num_digits,
                1 << digit_width,
            ) + 1,
        }
    }

    /// Creates parameters with given message_length (number of bits in the message) and digit
    /// width (number of bits in one digit, in the closed range 4, 8)
    pub const fn new_by_bit_length(number_of_bits: u32, digit_width: u32) -> Self {
        assert!(
            4 <= digit_width && digit_width <= 8,
            "You can only choose digit widths in the range [4, 8]"
        );
        let message_num_digits = number_of_bits.div_ceil(digit_width);
        Parameters {
            message_length: message_num_digits,
            digit_width,
            checksum_length: log_base_ceil(
                ((1 << digit_width) - 1) * message_num_digits,
                1 << digit_width,
            ) + 1,
        }
    }

    /// Maximum value of a digit
    pub const fn d(&self) -> u32 {
        (1 << self.digit_width) - 1
    }

    /// Number of bytes that can be represented at maximum with the parameters
    pub const fn byte_message_length(&self) -> u32 {
        (self.message_length * self.digit_width + 7) / 8
    }

    /// Total number of digits, i.e. sum of the number of digits in the actual message and the
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

fn wots_sign<const N: usize>(
    msg: &[u8; N.div_ceil(8)],
    secret_key: &[u8; 20 * key_width(N, WINTERNITZ_DIGIT_WIDTH)],
) -> [u8; 20 * key_width(N, WINTERNITZ_DIGIT_WIDTH)]
where
    [(); N.div_ceil(WINTERNITZ_DIGIT_WIDTH)]:,
    [(); checksum_width(N, WINTERNITZ_DIGIT_WIDTH)]:,
{
    let num_digits = N.div_ceil(WINTERNITZ_DIGIT_WIDTH);

    // Break the message up into an array of the individual WOTS digits.
    let mut digits = [0u8; N.div_ceil(WINTERNITZ_DIGIT_WIDTH)];

    // Starting with the left most bit (most significant) we iterate through the bits of the
    // original message. By the end of this for-loop we will have populated the digits array with
    // all of the digits of the message.
    //
    // TODO(proofofkeags): There is a *possible* subtle issue here where if we use a digit width
    // that doesn't divide a byte that we might not pad the correct side of the original message. It
    // is unclear whether the message would be left or right padded in this scenario and since the
    // BitVM implementation hard-codes everything to a digit width of 4, it's hard to know. This
    // likely will not be an issue in practice ever since it is extremely unlikely we will ever want
    // a digit width other than 4 but I include this note for completeness.
    for bit_idx in 0..N {
        // We map each bit to its byte index as well as a shift offset that within that byte that
        // we will use.
        let src_byte = bit_idx / 8;
        let src_bit = bit_idx % 8;

        // We also map each bit to its corresponding destination digit (corollary for the source
        // byte) as well as a shift offset within that digit. We also do a digit-wise reversal in
        // this step since BitVM demands that we arrange the digits in "little endian" order where
        // the least significant digit appears first in the array. As such, we take the most
        // significant bits (the ones with the lowest index) and map them to the last digits and
        // work our way backwards.
        let dest_digit = num_digits - 1 - bit_idx / WINTERNITZ_DIGIT_WIDTH;
        let dest_bit = bit_idx % WINTERNITZ_DIGIT_WIDTH;

        // We use the byte index and shift offset from the source message and translate it to a
        // single bit value {0, 1}.
        let bit = (msg[src_byte] >> (8 - 1 - src_bit)) & 1;

        // We or that bit together with the existing digits array at the proper digit index.
        digits[dest_digit] |= bit << (WINTERNITZ_DIGIT_WIDTH - 1 - dest_bit);
    }

    // Now that we have broken everything up into digits we are prepared to sign each individual
    // digit.
    let mut signature = [0; 20 * key_width(N, WINTERNITZ_DIGIT_WIDTH)];
    for idx in 0..num_digits {
        // We populate an initial array segment using the secret key bytes at the proper location.
        let segment: [u8; 20] = std::array::from_fn(|x| secret_key[x + 20 * idx]);

        // We initialize a hash with the raw byte value of the secret key.
        let mut hash = hash160::Hash::from_byte_array(segment);

        // Consistent with the WOTS protocol we iterate the hash chain forwards by the max digit
        // value minus the value of the digit being signed.
        for _ in 0..(WINTERNITZ_MAX_DIGIT as u8 - digits[idx]) {
            hash = hash160::Hash::hash(hash.as_ref());
        }

        // With the hash value computed, we memcpy it to its proper position in the signature array.
        signature[20 * idx..20 * (idx + 1)].copy_from_slice(hash.as_byte_array());
    }

    // At this point we now need to create and sign the checksum value. This part can be tricky with
    // rust's casting semantics so some of this code may be unnecessarily defensive.

    // The max checksum value drives how many bytes are ultimately allocated to the checksum itself.
    let max_checksum = num_digits * WINTERNITZ_MAX_DIGIT;
    let num_checksum_bytes = log_base_ceil(max_checksum as u32, 256) as usize;
    let num_checksum_digits = (num_checksum_bytes * 8).div_ceil(WINTERNITZ_DIGIT_WIDTH);

    // We compute the checksum value as the max possible checksum value minus the sum of all of the
    // digits.
    let checksum_val: u32 =
        (num_digits * WINTERNITZ_MAX_DIGIT - digits.iter().fold(0, |a, b| a + *b as usize)) as u32;

    // We create a checksum (de)accumulator since we will be applying destructive updates to it as
    // we incrementally compute the checksum signature.
    let mut checksum_acc = checksum_val;

    // We compute a 1 byte mask that we will use to mask off each digit that appears in the
    // checksum. We can get away with this approach since the checksum will never be larger than a
    // u64, so we can use shift operations the entire way. This didn't work with the original
    // message since we were operating over byte arrays instead of integer types.
    let mask = 0xFFu8 << (8 - WINTERNITZ_DIGIT_WIDTH) >> WINTERNITZ_DIGIT_WIDTH;

    // For each checksum digit we ...
    for checksum_digit_idx in 0..num_checksum_digits {
        // Here we initialize a byte array with the proper section of the secret key. This begins
        // after all of the original digits and is further indexed by the index of the checksum
        // digit we are working with right now.
        let segment: [u8; 20] =
            std::array::from_fn(|x| secret_key[x + 20 * (checksum_digit_idx + num_digits)]);

        // Again, we initialize a hash from those secret key bytes.
        let mut hash = hash160::Hash::from_byte_array(segment);

        // We iterate the hash forwards by MAX_DIGIT - actual digit which is computed by masking off
        // everything except the least significant digit width bits of our (de)accumulator.
        for _ in 0..(WINTERNITZ_MAX_DIGIT as u32 - (checksum_acc & mask as u32)) {
            hash = hash160::Hash::hash(hash.as_ref());
        }

        // With the hash value computed, we memcpy it to its proper position in the signature array.
        signature
            [20 * (num_digits + checksum_digit_idx)..20 * (num_digits + checksum_digit_idx + 1)]
            .copy_from_slice(hash.as_byte_array());

        // Finally we rightshift the checksum (de)accumulator by the digit width so that the new
        // least significant bits of the (de)accumulator are the next digit of the checkusm to be
        // signed.
        checksum_acc >>= WINTERNITZ_DIGIT_WIDTH;
    }

    // We finally have our signature.
    signature
}

// Taken from BitVM pile of amazing code.
const PARAMS_256: Parameters = Parameters::new_by_bit_length(256, WINTERNITZ_DIGIT_WIDTH as u32);
const PARAMS_256_TOTAL_LEN: usize = PARAMS_256.total_length() as usize;
const PARAMS_128: Parameters = Parameters::new_by_bit_length(128, WINTERNITZ_DIGIT_WIDTH as u32);
const PARAMS_128_TOTAL_LEN: usize = PARAMS_128.total_length() as usize;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_check() {
        let sk: [u8; 20 * PARAMS_128_TOTAL_LEN] = [0; 20 * PARAMS_128_TOTAL_LEN];
        let pk = wots_public_key::<PARAMS_128_TOTAL_LEN>(&PARAMS_128, &sk);
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

    #[test]
    fn test_key_width() {
        assert_eq!(key_width(128, 4), 36);
        assert_eq!(key_width(256, 4), 68);
    }
}
