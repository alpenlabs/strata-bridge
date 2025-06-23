//! WOTS implementation for the tx-graph.

#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use bitcoin::hashes::{hash160, Hash};
#[cfg(feature = "signing")]
use bitvm::signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256};

/// The digit width for the WOTS algorithm.
///
/// Changing this number may cause certain code to break as the signing code is not designed to
/// handle cases where the digit width doesn't divide byte width without residue.
pub const WINTERNITZ_DIGIT_WIDTH: usize = 4;

/// The maximum digit value for the WOTS algorithm.
pub const WINTERNITZ_MAX_DIGIT: usize = (2 << WINTERNITZ_DIGIT_WIDTH) - 1;

/// Calculates ceil(log_base(n))
pub const fn log_base_ceil(n: u32, base: u32) -> u32 {
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
pub const fn key_width(num_bits: usize, digit_width: usize) -> usize {
    let num_digits = num_bits.div_ceil(digit_width);
    num_digits + checksum_width(num_bits, digit_width)
}

/// Calculates the total WOTS key digits used for the checksum.
pub const fn checksum_width(num_bits: usize, digit_width: usize) -> usize {
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
    pub const fn max_digit_value(&self) -> u32 {
        (1 << self.digit_width) - 1
    }

    /// Number of bytes that can be represented at maximum with the parameters
    pub const fn byte_message_length(&self) -> u32 {
        (self.message_length * self.digit_width).div_ceil(8)
    }

    /// Total number of digits, i.e. sum of the number of digits in the actual message and the
    /// checksum
    pub const fn total_length(&self) -> u32 {
        self.message_length + self.checksum_length
    }
}

/// Returns the public key for the given secret key and the parameters
pub fn wots_public_key<const N: usize>(ps: &Parameters, secret_key: &[u8; 20 * N]) -> [u8; 20 * N]
where
    [(); 20 * N]:,
{
    let mut public_key = [0u8; 20 * N];
    for i in 0..ps.total_length() {
        let secret_i = {
            let mut buf = [0; 20];
            buf.copy_from_slice(&secret_key[20 * i as usize..20 * (i + 1) as usize]);
            buf
        };
        let mut hash = hash160::Hash::hash(&secret_i);
        for _ in 0..ps.max_digit_value() {
            hash = hash160::Hash::hash(&hash[..]);
        }

        let start = i as usize * 20;
        let end = start + 20;
        public_key[start..end].copy_from_slice(hash.as_byte_array());
    }
    public_key
}

/// Signs a 128 bit message with the given secret key.
#[cfg(feature = "signing")]
pub fn wots_sign_128_bitvm(
    msg: &[u8; 16],
    secret_key: &[u8; 20 * key_width(128, WINTERNITZ_DIGIT_WIDTH)],
) -> <wots_hash as Wots>::Signature {
    let split_secret_key: [Vec<u8>; key_width(128, WINTERNITZ_DIGIT_WIDTH)] =
        std::array::from_fn(|i| {
            let mut key = [0; 20];
            key.copy_from_slice(&secret_key[20 * i..20 * (i + 1)]);
            key.to_vec()
        });

    <wots_hash as Wots>::sign_with_secrets(&split_secret_key[..], msg)
}

/// Signs a 256 bit message with the given secret key.
#[cfg(feature = "signing")]
pub fn wots_sign_256_bitvm(
    msg: &[u8; 32],
    secret_key: &[u8; 20 * key_width(256, WINTERNITZ_DIGIT_WIDTH)],
) -> <wots256 as Wots>::Signature {
    let split_secret_key: [Vec<u8>; key_width(256, WINTERNITZ_DIGIT_WIDTH)] =
        std::array::from_fn(|i| {
            let mut key = [0; 20];
            key.copy_from_slice(&secret_key[20 * i..20 * (i + 1)]);
            key.to_vec()
        });

    wots256::sign_with_secrets(&split_secret_key[..], msg)
}

/// This function was an attempt at implementing WOTS signing from scratch. However during some
/// investigation into how this is implemented in BitVM it was determined to be incompatible for
/// some non-obvious reasons relating to how BitVM organizes it's signatures. We are leaving this
/// function here for now in case BitVM can use a more sane signature layout, but for now we are
/// using the fucked up BitVM version to guarantee compatibility while we pin down whether or not
/// the BitVM scheme is fixable without massively expanding the Bitcoin locking script sizes
/// required to guarantee the security of the bridge funds.
pub fn wots_sign_naive<const N: usize>(
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
/// The parameters for the 256-bit WOTS algorithm.
pub const PARAMS_256: Parameters =
    Parameters::new_by_bit_length(256, WINTERNITZ_DIGIT_WIDTH as u32);

/// The total length of the 256-bit WOTS parameters.
pub const PARAMS_256_TOTAL_LEN: usize = PARAMS_256.total_length() as usize;

/// The parameters for the 128-bit WOTS algorithm.
pub const PARAMS_128: Parameters =
    Parameters::new_by_bit_length(128, WINTERNITZ_DIGIT_WIDTH as u32);

/// The total length of the 128-bit WOTS parameters.
pub const PARAMS_128_TOTAL_LEN: usize = PARAMS_128.total_length() as usize;

#[cfg(test)]
#[cfg(feature = "signing")]
mod tests {
    use bitvm::{execute_script, treepp::script};

    use super::*;

    #[test]
    fn wots_pubkey_matches_bitvm() {
        // Generate a secret key, this could be random.
        let sk: [u8; 20 * 68] = std::array::from_fn(|i| (i / 20) as u8);

        // Generate the public key from the secret key.
        let pk = wots_public_key::<PARAMS_256_TOTAL_LEN>(&PARAMS_256, &sk);

        // Split the public key so we can compare it to bitvm output.
        let split_public_key: [[u8; 20]; key_width(256, WINTERNITZ_DIGIT_WIDTH)] =
            std::array::from_fn(|i| {
                let mut key = [0; 20];
                key.copy_from_slice(&pk[20 * i..20 * (i + 1)]);
                key
            });

        // Split that secret key so we can feed it to the bitvm implementation
        let split_secret_key: [Vec<u8>; key_width(256, WINTERNITZ_DIGIT_WIDTH)] =
            std::array::from_fn(|i| {
                let mut key = [0; 20];
                key.copy_from_slice(&sk[20 * i..20 * (i + 1)]);
                key.to_vec()
            });

        // Generate the public key with bitvm.
        let pk_bitvm = wots256::generate_public_key_with_secrets(&split_secret_key[..]);

        // Compare them.
        assert_eq!(pk_bitvm, split_public_key);
    }

    #[test]
    fn test_key_width() {
        assert_eq!(key_width(128, 4), 36);
        assert_eq!(key_width(256, 4), 68);
    }

    #[test]
    fn test_wots_256_sign() {
        let msg: [u8; 32] = std::array::from_fn(|i| 3 * i as u8);
        let sk: [u8; 20 * 68] = std::array::from_fn(|i| (i / 20) as u8);

        let sig = wots_sign_256_bitvm(&msg, &sk);

        let pk = wots_public_key::<68>(
            &Parameters::new_by_bit_length(256, WINTERNITZ_DIGIT_WIDTH as u32),
            &sk,
        );
        let mut pk_grouped = [[0u8; 20]; 68];
        for i in 0..68 {
            pk_grouped[i].copy_from_slice(&pk[20 * i..20 * (i + 1)]);
        }

        let scr = script! {
            { wots256::signature_to_raw_witness(&sig) }
            { wots256::checksig_verify(&pk_grouped) }
            for _ in 0..256/4 { OP_DROP } // drop data (in nibbles) from stack
            OP_TRUE
        };

        let res = execute_script(scr);
        assert!(res.success && res.final_stack.len() == 1);
    }

    #[test]
    fn test_wots_128_sign() {
        let msg: [u8; 16] = std::array::from_fn(|i| 3 * i as u8);
        let sk: [u8; 20 * 36] = std::array::from_fn(|i| (i / 20) as u8);

        let sig = wots_sign_128_bitvm(&msg, &sk);

        let pk = wots_public_key::<36>(
            &Parameters::new_by_bit_length(128, WINTERNITZ_DIGIT_WIDTH as u32),
            &sk,
        );
        let mut pk_grouped = [[0u8; 20]; 36];
        for i in 0..36 {
            pk_grouped[i].copy_from_slice(&pk[20 * i..20 * (i + 1)]);
        }

        let scr = script! {
            { wots_hash::signature_to_raw_witness(&sig) }
            { wots_hash::checksig_verify(&pk_grouped) }
            for _ in 0..128/4 { OP_DROP } // drop data (in nibbles) from stack
            OP_TRUE
        };

        let res = execute_script(scr);
        assert!(res.success && res.final_stack.len() == 1);
    }
}
