use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_groth16::{Proof, VerifyingKey};

pub const MASK: u8 = 0b11 << 6;

pub const COMPRESSED_POSTIVE: u8 = 0b10 << 6;
pub const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
pub const COMPRESSED_INFINITY: u8 = 0b01 << 6;

// pub const GROTH16_VK_BYTES: &[u8] = include_bytes!("../artifacts/sp1v3_groth16_vk.bin");

#[derive(Debug, PartialEq)]
pub enum CompressionFlag {
    Positive = COMPRESSED_POSTIVE as isize,
    Negative = COMPRESSED_NEGATIVE as isize,
    Infinity = COMPRESSED_INFINITY as isize,
}

impl From<u8> for CompressionFlag {
    fn from(val: u8) -> Self {
        match val {
            COMPRESSED_POSTIVE => CompressionFlag::Positive,
            COMPRESSED_NEGATIVE => CompressionFlag::Negative,
            COMPRESSED_INFINITY => CompressionFlag::Infinity,
            _ => panic!("Invalid compressed point flag"),
        }
    }
}

impl From<CompressionFlag> for u8 {
    fn from(value: CompressionFlag) -> Self {
        value as u8
    }
}

pub fn is_zeroed(first_byte: u8, buf: &[u8]) -> bool {
    if first_byte != 0 {
        return false;
    }
    for &b in buf {
        if b != 0 {
            return false;
        }
    }
    true
}

pub fn deserialize_with_flags(buf: &[u8; 32]) -> (Fq, CompressionFlag) {
    let m_data = buf[0] & MASK;
    if m_data == <CompressionFlag as Into<u8>>::into(CompressionFlag::Infinity) {
        if !is_zeroed(buf[0] & !MASK, &buf[1..32]) {
            panic!("invalid point")
        }
        (Fq::ZERO, CompressionFlag::Infinity)
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;
        let x = Fq::from_be_bytes_mod_order(&x_bytes);
        (x, m_data.into())
    }
}

pub fn g1_point_from_compressed_x_bytes(buf: &[u8; 32]) -> G1Affine {
    let (x, m_data) = deserialize_with_flags(buf);
    let (y, neg_y) = G1Affine::get_ys_from_x_unchecked(x).unwrap();
    let mut final_y = y;
    if y > neg_y {
        if m_data == CompressionFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressionFlag::Negative {
        final_y = -y;
    }
    G1Affine::new(x, final_y)
}

pub fn g1_point_from_compressed_x_unchecked_bytes(buf: &[u8; 32]) -> G1Affine {
    let (x, m_data) = deserialize_with_flags(buf);
    let (y, neg_y) = G1Affine::get_ys_from_x_unchecked(x).unwrap();

    let mut final_y = y;
    if y > neg_y {
        if m_data == CompressionFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressionFlag::Negative {
        final_y = -y;
    }
    G1Affine::new_unchecked(x, final_y)
}

pub fn g1_point_from_uncompressed_bytes(buf: &[u8; 64]) -> G1Affine {
    let (x_bytes, y_bytes) = buf.split_at(32);
    let x = Fq::from_be_bytes_mod_order(x_bytes);
    let y = Fq::from_be_bytes_mod_order(y_bytes);
    G1Affine::new(x, y)
}

pub fn g2_point_from_compressed_x_bytes(buf: &[u8; 64]) -> G2Affine {
    let (x1, flag) = deserialize_with_flags(&buf[..32].try_into().unwrap());
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]);
    let x = Fq2::new(x0, x1);

    if flag == CompressionFlag::Infinity {
        return G2Affine::identity();
    }

    let (y, neg_y) = G2Affine::get_ys_from_x_unchecked(x).unwrap();

    match flag {
        CompressionFlag::Positive => G2Affine::new(x, y),
        CompressionFlag::Negative => G2Affine::new(x, neg_y),
        _ => panic!("invalid point"),
    }
}

pub fn g2_point_from_compressed_x_bytes_unchecked(buf: &[u8; 64]) -> G2Affine {
    let (x1, flag) = deserialize_with_flags(&buf[..32].try_into().unwrap());
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]);
    let x = Fq2::new(x0, x1);

    if flag == CompressionFlag::Infinity {
        return G2Affine::identity();
    }

    let (y, neg_y) = G2Affine::get_ys_from_x_unchecked(x).unwrap();

    match flag {
        CompressionFlag::Positive => G2Affine::new_unchecked(x, y),
        CompressionFlag::Negative => G2Affine::new_unchecked(x, neg_y),
        _ => panic!("invalid point"),
    }
}

pub fn g2_point_from_uncompressed_bytes(buf: &[u8; 128]) -> G2Affine {
    let (x_bytes, y_bytes) = buf.split_at(64);
    let (x1_bytes, x0_bytes) = x_bytes.split_at(32);
    let (y1_bytes, y0_bytes) = y_bytes.split_at(32);

    let x1 = Fq::from_be_bytes_mod_order(x1_bytes);
    let x0 = Fq::from_be_bytes_mod_order(x0_bytes);
    let y1 = Fq::from_be_bytes_mod_order(y1_bytes);
    let y0 = Fq::from_be_bytes_mod_order(y0_bytes);

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    G2Affine::new(x, y)
}

pub fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Proof<Bn254> {
    let a = g1_point_from_uncompressed_bytes(buffer[..64].try_into().unwrap());
    let b = g2_point_from_uncompressed_bytes(buffer[64..192].try_into().unwrap());
    let c = g1_point_from_uncompressed_bytes(buffer[192..256].try_into().unwrap());
    Proof::<_> { a, b, c }
}

pub fn load_groth16_verifying_key_from_bytes(buffer: &[u8]) -> VerifyingKey<Bn254> {
    let alpha_g1 = g1_point_from_compressed_x_unchecked_bytes(&buffer[..32].try_into().unwrap());
    let _beta_g1 = g1_point_from_compressed_x_unchecked_bytes(&buffer[32..64].try_into().unwrap());
    let beta_g2 = g2_point_from_compressed_x_bytes_unchecked(&buffer[64..128].try_into().unwrap());
    let gamma_g2 =
        g2_point_from_compressed_x_bytes_unchecked(&buffer[128..192].try_into().unwrap());
    let _delta_g1 =
        g1_point_from_compressed_x_unchecked_bytes(&buffer[192..224].try_into().unwrap());
    let delta_g2 =
        g2_point_from_compressed_x_bytes_unchecked(&buffer[224..288].try_into().unwrap());

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut gamma_abc_g1 = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = g1_point_from_compressed_x_unchecked_bytes(
            &buffer[offset..offset + 32].try_into().unwrap(),
        );
        gamma_abc_g1.push(point);
        offset += 32;
    }
    VerifyingKey::<_> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}
