//! Test-only MuSig2 signer with counter-based nonce generation.
//!
//! **FOR TESTING ONLY - DO NOT USE IN PRODUCTION**

use musig2::{
    AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce, SecNonceSpices, sign_partial,
};
use secp256k1::{Message, PublicKey, SECP256K1, SecretKey};
use strata_bridge_primitives::secp::EvenSecretKey;

/// Test-only MuSig2 signer supporting multiple signing rounds.
///
/// Uses a nonce counter to participate in multiple rounds. Each round must use
/// a unique counter value. The same counter must be used for both `pubnonce()` and
/// `sign()` calls within the same round.
pub struct TestMusigSigner {
    operator_idx: u32,
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl TestMusigSigner {
    /// Create a new test signer.
    pub fn new(operator_idx: u32, secret_key: SecretKey) -> Self {
        let public_key = secret_key.public_key(SECP256K1);
        Self {
            operator_idx,
            secret_key,
            public_key,
        }
    }

    /// Generate deterministic nonce seed from operator index and nonce counter.
    fn nonce_seed(&self, nonce_counter: u64) -> [u8; 32] {
        let mut seed = [0u8; 32];
        seed[0..4].copy_from_slice(&self.operator_idx.to_be_bytes());
        seed[4..12].copy_from_slice(&nonce_counter.to_be_bytes());
        seed[12..].fill(0x42);
        seed
    }

    /// Generate secret nonce for a given round.
    fn secnonce(&self, agg_pubkey: PublicKey, nonce_counter: u64) -> SecNonce {
        SecNonce::build(self.nonce_seed(nonce_counter))
            .with_pubkey(self.public_key)
            .with_aggregated_pubkey(agg_pubkey)
            .with_extra_input(&self.operator_idx.to_be_bytes())
            .with_spices(SecNonceSpices::new().with_seckey(self.secret_key))
            .build()
    }

    /// Derive the public nonce for a given round.
    pub fn pubnonce(&self, agg_pubkey: PublicKey, nonce_counter: u64) -> PubNonce {
        self.secnonce(agg_pubkey, nonce_counter).public_nonce()
    }

    /// Sign for a given round. Must use the same `nonce_counter` as `pubnonce()`.
    pub fn sign(
        &self,
        key_agg_ctx: &KeyAggContext,
        nonce_counter: u64,
        agg_nonce: &AggNonce,
        message: Message,
    ) -> PartialSignature {
        let agg_pubkey = key_agg_ctx.aggregated_pubkey();
        let secnonce = self.secnonce(agg_pubkey, nonce_counter);

        sign_partial(
            key_agg_ctx,
            self.secret_key,
            secnonce,
            agg_nonce,
            message.as_ref(),
        )
        .expect("signing must succeed")
    }

    pub fn operator_idx(&self) -> u32 {
        self.operator_idx
    }

    pub fn pubkey(&self) -> PublicKey {
        self.public_key
    }
}

/// Creates deterministic test signers for a given operator count.
pub fn test_operator_signers(operator_count: usize) -> Vec<TestMusigSigner> {
    (0..operator_count)
        .map(|idx| {
            let byte =
                u8::try_from(idx + 1).expect("operator index too large for test key derivation");
            let sk = EvenSecretKey::from(SecretKey::from_slice(&[byte; 32]).unwrap());
            TestMusigSigner::new(idx as u32, *sk)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use musig2::{KeyAggContext, aggregate_partial_signatures, verify_partial};

    use super::*;

    fn make_test_operators(operator_count: usize) -> (Vec<TestMusigSigner>, Vec<PublicKey>) {
        let secret_keys: Vec<SecretKey> = (1..=operator_count)
            .map(|i| SecretKey::from_slice(&[i as u8; 32]).unwrap())
            .collect();

        let pubkeys: Vec<PublicKey> = secret_keys
            .iter()
            .map(|sk| sk.public_key(SECP256K1))
            .collect();

        let operators: Vec<TestMusigSigner> = secret_keys
            .into_iter()
            .enumerate()
            .map(|(i, sk)| TestMusigSigner::new(i as u32, sk))
            .collect();

        (operators, pubkeys)
    }

    fn assert_signing_works_for_operator_count(operator_count: usize) {
        let (operators, operator_pubkeys) = make_test_operators(operator_count);

        let key_agg_ctx = KeyAggContext::new(operator_pubkeys.clone()).expect("valid pubkeys");
        let aggregated_pubkey = key_agg_ctx.aggregated_pubkey();

        let message = Message::from_digest([0x42u8; 32]);
        let nonce_counter = 0u64;

        let operator_pubnonces: Vec<PubNonce> = operators
            .iter()
            .map(|op| op.pubnonce(aggregated_pubkey, nonce_counter))
            .collect();

        let aggregated_nonce = AggNonce::sum(operator_pubnonces.iter());

        let partial_sigs: Vec<PartialSignature> = operators
            .iter()
            .map(|op| op.sign(&key_agg_ctx, nonce_counter, &aggregated_nonce, message))
            .collect();

        for (i, ((sig, pubnonce), pubkey)) in partial_sigs
            .iter()
            .zip(operator_pubnonces.iter())
            .zip(operator_pubkeys.iter())
            .enumerate()
        {
            verify_partial(
                &key_agg_ctx,
                *sig,
                &aggregated_nonce,
                *pubkey,
                pubnonce,
                message.as_ref(),
            )
            .unwrap_or_else(|_| {
                panic!("invalid partial signature from operator {i} (count={operator_count})")
            });
        }

        let final_sig = aggregate_partial_signatures(
            &key_agg_ctx,
            &aggregated_nonce,
            partial_sigs,
            message.as_ref(),
        )
        .expect("aggregation should succeed");

        SECP256K1
            .verify_schnorr(
                &final_sig,
                &message,
                &aggregated_pubkey.x_only_public_key().0,
            )
            .expect("final aggregated signature verifies");
    }

    #[test]
    fn signing_works_for_1_2_3_operators() {
        for operator_count in [1usize, 2, 3] {
            assert_signing_works_for_operator_count(operator_count);
        }
    }
}
