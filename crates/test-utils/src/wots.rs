//! Test module related to `wots` keys and signatures.

use bitcoin::key::rand::{rngs::OsRng, Rng, RngCore};
use bitvm::{
    groth16::g16::{N_VERIFIER_FQS, N_VERIFIER_HASHES, N_VERIFIER_PUBLIC_INPUTS},
    signatures::wots::{wots160, wots256, wots32},
};
use strata_bridge_primitives::wots::{self, Groth16PublicKeys, Wots256PublicKey, Wots32PublicKey};

pub fn generate_wots_signatures() -> wots::Signatures {
    let wots256_signature: wots256::Signature = generate_byte_tuple_array(&mut OsRng);
    let wots32_signature: wots32::Signature = generate_byte_tuple_array(&mut OsRng);
    let wots160_signature: wots160::Signature = generate_byte_tuple_array(&mut OsRng);

    wots::Signatures {
        bridge_out_txid: wots256_signature,
        superblock_hash: wots256_signature,
        superblock_period_start_ts: wots32_signature,
        groth16: (
            [wots256_signature; N_VERIFIER_PUBLIC_INPUTS],
            [wots256_signature; N_VERIFIER_FQS],
            [wots160_signature; N_VERIFIER_HASHES],
        ),
    }
}

pub fn generate_wots_public_keys() -> wots::PublicKeys {
    let wots256_public_key: wots256::PublicKey = generate_byte_slice_array(&mut OsRng);
    let wots160_public_key: wots160::PublicKey = generate_byte_slice_array(&mut OsRng);
    let wots32_public_key: wots32::PublicKey = generate_byte_slice_array(&mut OsRng);

    let bridge_out_txid = Wots256PublicKey(wots256_public_key);
    let superblock_hash = Wots256PublicKey(wots256_public_key);
    let superblock_period_start_ts = Wots32PublicKey(wots32_public_key);

    wots::PublicKeys {
        bridge_out_txid,
        superblock_hash,
        superblock_period_start_ts,
        groth16: Groth16PublicKeys((
            [wots256_public_key; N_VERIFIER_PUBLIC_INPUTS],
            [wots256_public_key; N_VERIFIER_FQS],
            [wots160_public_key; N_VERIFIER_HASHES],
        )),
    }
}

fn generate_byte_slice_array<const SLICE_SIZE: usize, const LENGTH: usize>(
    rng: &mut impl RngCore,
) -> [[u8; SLICE_SIZE]; LENGTH] {
    std::array::from_fn(|_| {
        let mut byte_slice = [0u8; SLICE_SIZE];
        rng.fill_bytes(&mut byte_slice);

        byte_slice
    })
}

fn generate_byte_tuple_array<const SLICE_SIZE: usize, const LENGTH: usize>(
    rng: &mut impl RngCore,
) -> [([u8; SLICE_SIZE], u8); LENGTH] {
    std::array::from_fn(|_| {
        let mut byte_slice = [0u8; SLICE_SIZE];
        rng.fill_bytes(&mut byte_slice);

        (byte_slice, rng.gen_range(0..u8::MAX))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_byte_slice_array() {
        let wots256_public_key: wots256::PublicKey =
            generate_byte_slice_array::<20, 67>(&mut OsRng);
        let wots160_public_key: wots160::PublicKey =
            generate_byte_slice_array::<20, 43>(&mut OsRng);
        let wots32_public_key: wots32::PublicKey = generate_byte_slice_array::<20, 10>(&mut OsRng);

        assert_eq!(wots256_public_key.len(), 67, "wots256 size should match");
        assert_eq!(wots160_public_key.len(), 43, "wots160 size should match");
        assert_eq!(wots32_public_key.len(), 10, "wots32 size should match");
    }
}
