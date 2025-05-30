//! Module for test-utilities related to `musig2`.

use bitcoin::key::rand::{rngs::OsRng, Rng};
use musig2::{
    aggregate_partial_signatures,
    secp256k1::{schnorr::Signature, Keypair, Message, SecretKey},
    sign_partial, AggNonce, KeyAggContext, NonceSeed, PartialSignature, PubNonce, SecNonce,
};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

const NONCE_SEED_SIZE: usize = 32;

/// Generates a random public nonce.
pub fn generate_pubnonce() -> PubNonce {
    let sec_nonce = generate_secnonce();

    sec_nonce.public_nonce()
}

/// Generates a random secret nonce.
pub fn generate_secnonce() -> SecNonce {
    let mut nonce_seed_bytes = [0u8; NONCE_SEED_SIZE];
    OsRng.fill(&mut nonce_seed_bytes);
    let nonce_seed = NonceSeed::from(nonce_seed_bytes);

    SecNonce::build(nonce_seed).build()
}

/// Generates a random partial signature.
pub fn generate_partial_signature() -> PartialSignature {
    let secret_key = SecretKey::new(&mut OsRng);

    PartialSignature::from_slice(secret_key.as_ref())
        .expect("should be able to generate arbitrary partial signature")
}

/// Generates a random aggregated nonce.
pub fn generate_agg_nonce() -> AggNonce {
    let pubnonce1 = generate_pubnonce();
    let pubnonce2 = generate_pubnonce();

    [pubnonce1, pubnonce2].iter().cloned().sum()
}

/// Generates a musig2-aggregated signature from a single keypair.
///
/// This means that we assume that the provided keypair is the only in the musig2 set.
/// This is useful for testing the tx graph without requiring a full operator set.
pub fn generate_agg_signature(
    message: &Message,
    keypair: &Keypair,
    witness: &TaprootWitness,
) -> Signature {
    let secret_key = keypair.secret_key();
    let public_key = keypair.public_key();

    let mut key_agg_ctx =
        KeyAggContext::new([public_key]).expect("must be able to aggregate a single pubkey");

    match witness {
        TaprootWitness::Key => {
            key_agg_ctx = key_agg_ctx
                .with_unspendable_taproot_tweak()
                .expect("must be able to tweak the key agg context")
        }
        TaprootWitness::Tweaked { tweak } => {
            key_agg_ctx = key_agg_ctx
                .with_taproot_tweak(tweak.as_ref())
                .expect("must be able to tweak the key agg context")
        }
        _ => {}
    }

    let secnonce = SecNonce::build([0u8; 32])
        .with_seckey(secret_key)
        .with_message(message.as_ref())
        .with_aggregated_pubkey(public_key)
        .build();

    let pubnonce = secnonce.public_nonce();
    let agg_nonce: AggNonce = [pubnonce].iter().cloned().sum();

    let partial_sig: PartialSignature = sign_partial(
        &key_agg_ctx,
        secret_key,
        secnonce,
        &agg_nonce,
        message.as_ref(),
    )
    .expect("must be able to sign with partial signature");

    aggregate_partial_signatures(&key_agg_ctx, &agg_nonce, [partial_sig], message.as_ref())
        .expect("must be able to aggregate partial signatures")
}
