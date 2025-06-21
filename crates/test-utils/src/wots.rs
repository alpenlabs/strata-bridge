//! Test module related to `wots` keys and signatures.

use std::sync::Arc;

use bitcoin::key::rand::{rngs::OsRng, Rng, RngCore};
use bitvm::{
    chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256},
    signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256},
};
use strata_bridge_primitives::wots::{
    self, Groth16PublicKeys, Groth16Sigs, Wots256PublicKey, Wots256Sig,
};

/// Generates a random WOTS signature.
pub fn generate_wots_signatures() -> wots::Signatures {
    let wots256_signature: <wots256 as Wots>::Signature = generate_sig_array(&mut OsRng);
    let wots_hash_signature: <wots_hash as Wots>::Signature = generate_sig_array(&mut OsRng);

    wots::Signatures {
        withdrawal_fulfillment: Wots256Sig(wots256_signature),
        groth16: Groth16Sigs((
            [wots256_signature; NUM_PUBS].into(),
            [wots256_signature; NUM_U256].into(),
            [wots_hash_signature; NUM_HASH].into(),
        )),
    }
}

/// Generates a random WOTS public key.
pub fn generate_wots_public_keys() -> wots::PublicKeys {
    let wots256_public_key: <wots256 as Wots>::PublicKey = generate_byte_slice_array(&mut OsRng);
    let wots_hash_public_key: <wots_hash as Wots>::PublicKey =
        generate_byte_slice_array(&mut OsRng);

    let withdrawal_fulfillment = Wots256PublicKey(Arc::new(wots256_public_key));

    wots::PublicKeys {
        withdrawal_fulfillment,
        groth16: Groth16PublicKeys(Arc::new((
            [wots256_public_key; NUM_PUBS],
            [wots256_public_key; NUM_U256],
            [wots_hash_public_key; NUM_HASH],
        ))),
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

fn generate_sig_array<const LENGTH: usize>(rng: &mut impl RngCore) -> [[u8; 21]; LENGTH] {
    std::array::from_fn(|_| {
        let mut byte_slice = [0u8; 20];
        rng.fill_bytes(&mut byte_slice);

        let mut result = Vec::with_capacity(21);
        result.extend_from_slice(&byte_slice);
        result.push(rng.gen_range(0..u8::MAX));

        result.try_into().expect("must be 21 bytes")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_byte_slice_array() {
        let wots256_public_key: <wots256 as Wots>::PublicKey =
            generate_byte_slice_array::<20, 68>(&mut OsRng);
        let wots_hash_public_key: <wots_hash as Wots>::PublicKey =
            generate_byte_slice_array::<20, 36>(&mut OsRng);

        assert_eq!(wots256_public_key.len(), 68, "wots256 size should match");
        assert_eq!(
            wots_hash_public_key.len(),
            36,
            "wots_hash size should match"
        );
    }
}
