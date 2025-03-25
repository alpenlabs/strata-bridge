//! Test module related to `wots` keys and signatures.

use bitcoin::key::rand::{rngs::OsRng, Rng, RngCore};
use bitvm::{
    chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256},
    signatures::wots_api::{wots256, wots_hash},
};
use strata_bridge_primitives::wots::{
    self, Groth16PublicKeys, Groth16Signatures, Wots256PublicKey, Wots256Signature,
};

pub fn generate_wots_signatures() -> wots::Signatures {
    let wots256_signature: wots256::Signature = generate_byte_tuple_array(&mut OsRng);
    let wots_hash_signature: wots_hash::Signature = generate_byte_tuple_array(&mut OsRng);

    wots::Signatures {
        withdrawal_fulfillment: Wots256Signature(wots256_signature),
        groth16: Groth16Signatures((
            [wots256_signature; NUM_PUBS].into(),
            [wots256_signature; NUM_U256].into(),
            [wots_hash_signature; NUM_HASH].into(),
        )),
    }
}

pub fn generate_wots_public_keys() -> wots::PublicKeys {
    let wots256_public_key: wots256::PublicKey = generate_byte_slice_array(&mut OsRng);
    let wots_hash_public_key: wots_hash::PublicKey = generate_byte_slice_array(&mut OsRng);

    let withdrawal_fulfillment = Wots256PublicKey(wots256_public_key);

    wots::PublicKeys {
        withdrawal_fulfillment,
        groth16: Groth16PublicKeys((
            [wots256_public_key; NUM_PUBS],
            [wots256_public_key; NUM_U256],
            [wots_hash_public_key; NUM_HASH],
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
            generate_byte_slice_array::<20, 68>(&mut OsRng);
        let wots_hash_public_key: wots_hash::PublicKey =
            generate_byte_slice_array::<20, 36>(&mut OsRng);

        assert_eq!(wots256_public_key.len(), 68, "wots256 size should match");
        assert_eq!(
            wots_hash_public_key.len(),
            44,
            "wots_hash size should match"
        );
    }
}
