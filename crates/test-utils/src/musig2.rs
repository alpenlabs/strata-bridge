//! Module for test-utilities related to `musig2`.

use bitcoin::key::rand::{rngs::OsRng, Rng};
use musig2::{secp256k1::SecretKey, NonceSeed, PartialSignature, PubNonce, SecNonce};

const NONCE_SEED_SIZE: usize = 32;

pub fn generate_pubnonce() -> PubNonce {
    let sec_nonce = generate_secnonce();

    sec_nonce.public_nonce()
}

pub fn generate_secnonce() -> SecNonce {
    let mut nonce_seed_bytes = [0u8; NONCE_SEED_SIZE];
    OsRng.fill(&mut nonce_seed_bytes);
    let nonce_seed = NonceSeed::from(nonce_seed_bytes);

    SecNonce::build(nonce_seed).build()
}

pub fn generate_partial_signature() -> PartialSignature {
    let secret_key = SecretKey::new(&mut OsRng);

    PartialSignature::from_slice(secret_key.as_ref())
        .expect("should be able to generate arbitary partial signature")
}
