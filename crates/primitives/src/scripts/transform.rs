use bitvm::{bigint::U254, bn254::chunk_superblock::H256, pseudo::NMUL, treepp::*};

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
    const N_DIGITS: u32 = (U254::N_BITS + WINDOW - 1) / WINDOW;

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

pub fn sb_hash_from_nibbles() -> Script {
    const WINDOW: u32 = 4;
    const LIMB_SIZE: u32 = 30;
    const N_DIGITS: u32 = (H256::N_BITS + WINDOW - 1) / WINDOW;

    script! {
        for i in 1..64 { { i } OP_ROLL }
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
        for _ in 1..H256::N_LIMBS { OP_FROMALTSTACK }
        for i in 1..H256::N_LIMBS { { i } OP_ROLL }
    }
}

pub fn sb_hash_from_bytes() -> Script {
    const WINDOW: u32 = 8;
    const LIMB_SIZE: u32 = 30;
    const N_DIGITS: u32 = (H256::N_BITS + WINDOW - 1) / WINDOW;

    script! {
        for i in 1..32 { { i } OP_ROLL }
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
        for _ in 1..H256::N_LIMBS { OP_FROMALTSTACK }
        for i in 1..H256::N_LIMBS { { i } OP_ROLL }
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

pub fn extract_superblock_ts_from_header() -> Script {
    script! {
        for i in 0..4 { { 80 - 12 + 2 * i } OP_PICK }
        for _ in 1..4 {  { NMUL(1 << 8) } OP_ADD }
    }
}

pub fn add_bincode_padding_bytes32() -> Script {
    script! {
        for b in [0; 7] { {b} } 32
    }
}

#[cfg(test)]
mod tests {
    use bitvm::treepp::*;

    use super::*;

    #[test]
    fn test_flip_byts_nibbles() {
        let script = script! {
            { 0xf9 }
            flip_byte_nibbles
            { 0x9f }
            OP_EQUAL
        };
        let res = execute_script(script);
        assert!(res.success);
    }
}
