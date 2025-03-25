use bitvm::{bigint::U254, pseudo::NMUL, treepp::*};

fn split_digit(window: u32, index: u32) -> Script {
    script! {
        // {v}
        0                           // {v} {A}
        OP_SWAP
        for i in 0..index {
            OP_TUCK                 // {v} {A} {v}
            { 1 << (window - i - 1) }   // {v} {A} {v} {1000}
            OP_GREATERTHANOREQUAL   // {v} {A} {1/0}
            OP_TUCK                 // {v} {1/0} {A} {1/0}
            OP_ADD                  // {v} {1/0} {A+1/0}
            if i < index - 1 { { NMUL(2) } }
            OP_ROT OP_ROT
            OP_IF
                { 1 << (window - i - 1) }
                OP_SUB
            OP_ENDIF
        }
        OP_SWAP
    }
}

pub fn ts_from_nibbles() -> Script {
    script! {
        // [a]
        for _ in 1..8 { OP_TOALTSTACK }
        for _ in 1..8 {
            { NMUL(1 << 4) } OP_FROMALTSTACK OP_ADD
        }
    }
}

pub fn fq_from_nibbles() -> Script {
    const WINDOW: u32 = 4;
    const LIMB_SIZE: u32 = 29;
    const N_DIGITS: u32 = U254::N_BITS.div_ceil(WINDOW);

    script! {
        for i in (1..=N_DIGITS).rev() {
            if (i * WINDOW) % LIMB_SIZE == 0 {
                OP_TOALTSTACK
            } else if (i * WINDOW) % LIMB_SIZE > 0 &&
                        (i * WINDOW) % LIMB_SIZE < WINDOW {
                OP_SWAP
                { split_digit(WINDOW, (i * WINDOW) % LIMB_SIZE) }
                OP_ROT
                { NMUL(1 << ((i * WINDOW) % LIMB_SIZE)) }
                OP_ADD
                OP_TOALTSTACK
            } else if i != N_DIGITS {
                { NMUL(1 << WINDOW) }
                OP_ADD
            }
        }
        for _ in 1..U254::N_LIMBS { OP_FROMALTSTACK }
        for i in 1..U254::N_LIMBS { { i } OP_ROLL }
    }
}

pub fn flip_byte_nibbles() -> Script {
    script! {
        for i in 1..=4 {
            { 1 << (8 - i) }
            OP_2DUP
            OP_GREATERTHAN
            OP_IF OP_SUB { 1 << (4 - i) }
            OP_ELSE OP_DROP 0
            OP_ENDIF
            OP_TOALTSTACK
        }
        { NMUL(1 << 4) }
        for _ in 0..4 { OP_FROMALTSTACK OP_ADD }
    }
}

pub fn hash_to_bn254_fq() -> Script {
    script! {
        for i in 1..=3 {
            { 1 << (8 - i) }
            OP_2DUP
            OP_GREATERTHAN
            OP_IF OP_SUB
            OP_ELSE OP_DROP
            OP_ENDIF
        }
    }
}

pub fn add_bincode_padding_bytes32() -> Script {
    script! {
        for b in [0; 7] { {b} } 32
    }
}

/// Extracts the committed adta from a WOTS signature.
///
/// It assumes that that the signature consists of a 4-byte checksum that is removed.
/// The remaining data is assumed to be in the form of nibbles in little-endian order (i.e., the MSB
/// first). These nibbles are then converted to bytes. Thus, the output has `(TOTAL_SIZE - 4) / 2`
/// bytes.
pub fn wots_to_byte_array<const TOTAL_SIZE: usize>(
    signature: [([u8; 20], u8); TOTAL_SIZE],
) -> [u8; (TOTAL_SIZE - 4) / 2]
where
    [(); (TOTAL_SIZE - 4) / 2]:, // must be a multiple of 4 (number of bits in a nibble)
{
    let nibs = signature.iter().map(|(_, digit)| *digit);
    // [MSB, LSB, MSB, LSB, ..., checksum]
    // remove checksum to get [MSB, LSB, MSB, LSB, ...]
    let nibs = nibs.take(TOTAL_SIZE - 4);

    let nibs = nibs.rev(); // sigs are obtained in reverse order so undo
                           // [LSB, MSB, LSB, MSB,.., LSB]

    let data = nibs
        .array_chunks::<2>()
        .map(|bn| (bn[1] << 4) + bn[0]) // endian assumed by wots
        .collect::<Vec<u8>>();

    data.try_into()
        .expect("must have the correct size due to the computation above")
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::{self, Hash},
        hex::DisplayHex,
    };
    use bitvm::{
        signatures::wots_api::{wots256, wots_hash},
        treepp::*,
    };
    use secp256k1::rand::{rngs::OsRng, Rng};

    use super::*;

    #[test]
    fn test_flip_bytes_nibbles() {
        let script = script! {
            { 0xf9 }
            flip_byte_nibbles
            { 0x9f }
            OP_EQUAL
        };
        let res = execute_script(script);
        assert!(res.success);
    }

    #[test]
    fn test_wots_to_byte_array() {
        let secret_str = "test_wots_to_byte_array".to_string();
        let secret = hashes::sha256::Hash::hash(secret_str.as_bytes())
            .to_byte_array()
            .to_lower_hex_string();

        let message_bytes = OsRng.gen::<[u8; 20]>();
        let signatures = wots_hash::get_signature(&secret, &message_bytes);

        let committed_data = wots_to_byte_array(signatures);

        assert_eq!(
            message_bytes.to_vec(),
            committed_data,
            "committed and extracted 160-bit data must match"
        );

        let message_bytes = OsRng.gen::<[u8; 32]>();
        let signatures = wots256::get_signature(&secret, &message_bytes);

        let committed_data = wots_to_byte_array(signatures);

        assert_eq!(
            message_bytes.to_vec(),
            committed_data,
            "committed and extracted 256-bit data must match"
        );
    }
}
