//! This module contains primitive operations for chunking and hashing field elements.
//!
//! Source: https://github.com/alpenlabs/BitVM/blob/feat/fp12_squaring_tap/src/chunk/primitves.rs
use ark_ff::BigInt;

pub(super) fn extern_hash_fps(fqs: Vec<ark_bn254::Fq>, mode: bool) -> [u8; 64] {
    let mut msgs: Vec<[u8; 64]> = Vec::new();
    for fq in fqs {
        let v = fq_to_chunked_bits(fq.into(), 4);
        let nib_arr: Vec<u8> = v.into_iter().map(|x| x as u8).collect();
        msgs.push(nib_arr.try_into().unwrap());
    }
    extern_hash_nibbles(msgs, mode)
}

pub(super) fn extern_fq_to_nibbles(msg: ark_bn254::Fq) -> [u8; 64] {
    let v = fq_to_chunked_bits(msg.into(), 4);
    let vu8: Vec<u8> = v.iter().map(|x| (*x) as u8).collect();
    vu8.try_into().unwrap()
}

pub(super) fn fq_to_chunked_bits(fq: BigInt<4>, limb_size: usize) -> Vec<u32> {
    let bits: Vec<bool> = ark_ff::BitIteratorBE::new(fq.as_ref()).collect();
    assert!(bits.len() == 256);
    bits.chunks(limb_size)
        .map(|chunk| {
            let mut factor = 1;
            let res = chunk.iter().rev().fold(0, |acc, &x| {
                let r = acc + if x { factor } else { 0 };
                factor *= 2;
                r
            });
            res
        })
        .collect()
}

pub(super) fn nib_to_byte_array(digits: &[u8]) -> Vec<u8> {
    let mut msg_bytes = Vec::with_capacity(digits.len() / 2);

    for nibble_pair in digits.chunks(2) {
        let byte = (nibble_pair[1] << 4) | (nibble_pair[0] & 0b00001111);
        msg_bytes.push(byte);
    }

    msg_bytes
}

pub(super) fn extern_hash_nibbles(msgs: Vec<[u8; 64]>, mode: bool) -> [u8; 64] {
    assert!(msgs.len() == 4 || msgs.len() == 2 || msgs.len() == 12 || msgs.len() == 6);

    if msgs.len() == 4 {
        extern_hash_fp_var(msgs)
    } else if msgs.len() == 12 {
        if mode {
            extern_hash_fp12(msgs)
        } else {
            extern_hash_fp12_v2(msgs)
        }
    } else if msgs.len() == 2 {
        extern_hash_fp_var(msgs)
    } else if msgs.len() == 6 {
        extern_hash_fp6(msgs)
    } else {
        panic!()
    }
}

fn hex_string_to_nibble_array(hex_string: &str) -> Vec<u8> {
    hex_string
        .chars()
        .map(|c| c.to_digit(16).expect("Invalid hex character") as u8) // Convert each char to a nibble
        .collect()
}

fn extern_hash_fp_var(fqs: Vec<[u8; 64]>) -> [u8; 64] {
    let mut vs = Vec::new();
    for fq in fqs {
        let v = fq.to_vec();
        vs.extend_from_slice(&v);
    }
    let nib_arr: Vec<u8> = vs.clone().into_iter().collect();
    let p_bytes: Vec<u8> = nib_to_byte_array(&nib_arr);

    let hash_out = blake3::hash(&p_bytes).to_string();

    let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32 - 20) * 2);
    let res = hex_string_to_nibble_array(&hash_out);
    res.try_into().unwrap()
}

fn extern_hash_fp12(fqs: Vec<[u8; 64]>) -> [u8; 64] {
    let hash_out_first = extern_hash_fp6(fqs[0..6].to_vec());
    let mut hash_out_second = extern_hash_fp6(fqs[6..12].to_vec()).to_vec();
    hash_out_second.extend_from_slice(&hash_out_first);
    let p_bytes: Vec<u8> = nib_to_byte_array(&hash_out_second);
    let hash_out = blake3::hash(&p_bytes).to_string();
    let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32 - 20) * 2);
    let hash_out = hex_string_to_nibble_array(&hash_out);
    hash_out.try_into().unwrap()
}

fn extern_hash_fp12_v2(fqs: Vec<[u8; 64]>) -> [u8; 64] {
    let hash_out_first = extern_hash_fp_var(fqs[0..6].to_vec());
    let mut hash_out_second = extern_hash_fp_var(fqs[6..12].to_vec()).to_vec();
    hash_out_second.extend_from_slice(&hash_out_first);
    let p_bytes: Vec<u8> = nib_to_byte_array(&hash_out_second);
    let hash_out = blake3::hash(&p_bytes).to_string();
    let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32 - 20) * 2);
    let hash_out = hex_string_to_nibble_array(&hash_out);
    hash_out.try_into().unwrap()
}

fn extern_hash_fp6(fqs: Vec<[u8; 64]>) -> [u8; 64] {
    let hash_out_first = extern_hash_fp_var(fqs[0..2].to_vec());
    let mut hash_out_second = extern_hash_fp_var(fqs[2..6].to_vec()).to_vec();
    hash_out_second.extend_from_slice(&hash_out_first);
    let p_bytes: Vec<u8> = nib_to_byte_array(&hash_out_second);
    let hash_out = blake3::hash(&p_bytes).to_string();
    let hash_out = replace_first_n_with_zero(&hash_out.to_string(), (32 - 20) * 2);
    let hash_out = hex_string_to_nibble_array(&hash_out);
    hash_out.try_into().unwrap()
}

fn replace_first_n_with_zero(hex_string: &str, n: usize) -> String {
    let mut result = String::new();

    if hex_string.len() <= n {
        result.push_str(&"0".repeat(hex_string.len())); // If n >= string length, replace all
    } else {
        result.push_str(&"0".repeat(n)); // Replace first n characters
        result.push_str(&hex_string[0..(hex_string.len() - n)]); // Keep the rest of the string
    }
    result
}
