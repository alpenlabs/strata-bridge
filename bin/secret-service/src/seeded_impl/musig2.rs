//! In-memory persistence for MuSig2's secret data.

use std::{
    collections::HashMap,
    hash::{BuildHasher, RandomState},
    sync::LazyLock,
};

use bitcoin::{
    bip32::Xpriv,
    hashes::Hash as _,
    key::{Keypair, Parity, TapTweak},
    TapNodeHash, XOnlyPublicKey,
};
use cache_advisor::CacheAdvisor;
use hkdf::Hkdf;
use make_buf::make_buf;
use musig2::{
    errors::SigningError,
    secp::{MaybePoint, Point},
    secp256k1::{schnorr::Signature, Message, SECP256K1},
    AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce, SecNonceSpices,
};
use secret_service_proto::v2::traits::{
    Musig2Params, Musig2Signer, Origin, OurPubKeyIsNotInParams, SchnorrSigner, SelfVerifyFailed,
    Server,
};
use sha2::Sha256;
use strata_bridge_primitives::{scripts::taproot::TaprootWitness, secp::EvenSecretKey};
use terrors::OneOf;
use tokio::sync::Mutex;

use super::paths::{MUSIG2_KEY_PATH, MUSIG2_NONCE_IKM_PATH};

/// Secret data for the MuSig2 signer.
#[derive(Debug)]
pub struct Ms2Signer {
    /// Operator's [`Keypair`].
    kp: Keypair,

    /// Initial key material to derive secret nonces.
    ikm: [u8; 32],
}

const SECNONCE_CACHE_CAPACITY: usize = 512;
const SECNONCE_CACHE_ENTRY_PCT: u8 = 10;
const SECNONCE_CACHE_REALLOC_THRESHOLD: usize = 64;

static SECNONCE_CACHE: LazyLock<Mutex<SecNonceCache>> = LazyLock::new(|| {
    Mutex::new(SecNonceCache::new(
        SECNONCE_CACHE_CAPACITY,
        SECNONCE_CACHE_ENTRY_PCT,
        RandomState::new(),
    ))
});

struct SecNonceCache<S = RandomState>
where
    S: BuildHasher,
{
    cache: HashMap<u64, SecNonce>,
    advisor: CacheAdvisor,
    hash_builder: S,
}

impl<S> SecNonceCache<S>
where
    S: BuildHasher,
{
    fn new(capacity: usize, entry_pct: u8, hash_builder: S) -> Self {
        Self {
            cache: HashMap::with_capacity(capacity),
            advisor: CacheAdvisor::new(capacity, entry_pct),
            hash_builder,
        }
    }

    fn get(
        &mut self,
        params: &Musig2Params,
        create: impl FnOnce(&Musig2Params) -> Result<SecNonce, OurPubKeyIsNotInParams>,
    ) -> Result<SecNonce, OurPubKeyIsNotInParams> {
        let hash = self.hash_builder.hash_one(params);
        if let Some(nonce) = self.cache.get(&hash) {
            Ok(nonce.clone())
        } else {
            let nonce = create(params)?;
            let eviction_list = self.advisor.accessed_reuse_buffer(hash, 1);
            for (id_to_evict, _) in eviction_list {
                self.cache.remove(id_to_evict);
            }

            if eviction_list.len() > SECNONCE_CACHE_REALLOC_THRESHOLD {
                self.advisor.reset_internal_access_buffer();
            }
            self.cache.insert(hash, nonce.clone());
            Ok(nonce)
        }
    }
}

impl Ms2Signer {
    /// Creates a new MuSig2 signer given a master [`Xpriv`].
    pub fn new(base: &Xpriv) -> Self {
        let key = base
            .derive_priv(SECP256K1, &MUSIG2_KEY_PATH)
            .expect("valid key")
            .private_key;
        let ikm = base
            .derive_priv(SECP256K1, &MUSIG2_NONCE_IKM_PATH)
            .expect("valid child")
            .private_key
            .secret_bytes();
        Self {
            kp: Keypair::from_secret_key(SECP256K1, &EvenSecretKey::from(key)),
            ikm,
        }
    }

    fn key_agg_ctx(params: &Musig2Params) -> KeyAggContext {
        let mut ctx = KeyAggContext::new(
            params
                .ordered_pubkeys
                .iter()
                .map(|pk| pk.public_key(Parity::Even)),
        )
        .unwrap();

        match params.witness {
            TaprootWitness::Key => {
                ctx = ctx
                    .with_unspendable_taproot_tweak()
                    .expect("must be able to tweak the key agg context")
            }
            TaprootWitness::Tweaked { tweak } => {
                ctx = ctx
                    .with_taproot_tweak(tweak.as_ref())
                    .expect("must be able to tweak the key agg context")
            }
            _ => {}
        }
        ctx
    }

    async fn sec_nonce(
        &self,
        params: &Musig2Params,
        key_agg_ctx: &KeyAggContext,
    ) -> Result<SecNonce, OurPubKeyIsNotInParams> {
        SECNONCE_CACHE.lock().await.get_or_set(params, |params| {
            let nonce_seed = {
                let info = make_buf! {
                    (&params.input.txid.as_raw_hash().to_byte_array(), 32),
                    (&params.input.vout.to_le_bytes(), 4)
                };
                let hk = Hkdf::<Sha256>::new(None, &self.ikm);
                let mut output = [0u8; 32];
                hk.expand(&info, &mut output)
                    .expect("32 is a valid length for Sha256 to output");
                output
            };

            let our_signer_idx = params
                .ordered_pubkeys
                .iter()
                .position(|pk| pk == &self.kp.x_only_public_key().0)
                .ok_or(OurPubKeyIsNotInParams)?;

            let secnonce = SecNonce::build(nonce_seed)
                .with_pubkey(self.kp.public_key())
                .with_aggregated_pubkey(key_agg_ctx.aggregated_pubkey::<Point>())
                .with_extra_input(&(our_signer_idx as u32).to_be_bytes())
                .with_spices(SecNonceSpices::new().with_seckey(self.kp.secret_key()))
                .build();
            Ok(secnonce)
        })
    }
}

impl Musig2Signer<Server> for Ms2Signer {
    async fn get_pub_nonce(
        &self,
        params: Musig2Params,
    ) -> Result<PubNonce, OurPubKeyIsNotInParams> {
        let key_agg_ctx = Self::key_agg_ctx(&params);
        self.sec_nonce(&params, &key_agg_ctx)
            .await
            .map(|sn| sn.public_nonce())
    }

    async fn get_our_partial_sig(
        &self,
        params: Musig2Params,
        aggnonce: AggNonce,
        message: [u8; 32],
    ) -> Result<PartialSignature, OneOf<(OurPubKeyIsNotInParams, SelfVerifyFailed)>> {
        let key_agg_ctx = Self::key_agg_ctx(&params);
        let secnonce = self
            .sec_nonce(&params, &key_agg_ctx)
            .await
            .map_err(OneOf::new)?;
        let partial_signature = match musig2::adaptor::sign_partial::<PartialSignature>(
            &key_agg_ctx,
            self.kp.secret_key(),
            secnonce,
            &aggnonce,
            MaybePoint::Infinity,
            message,
        ) {
            Ok(ps) => ps,
            Err(SigningError::UnknownKey) => {
                unreachable!("we checked if our key is included when building secnonce")
            }
            Err(SigningError::SelfVerifyFail) => return Err(OneOf::new(SelfVerifyFailed)),
        };
        Ok(partial_signature)
    }
}

impl SchnorrSigner<Server> for Ms2Signer {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Server as Origin>::Container<Signature> {
        self.kp
            .tap_tweak(SECP256K1, tweak)
            .to_keypair()
            .sign_schnorr(Message::from_digest_slice(digest).expect("digest is 32 bytes"))
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Server as Origin>::Container<Signature> {
        self.kp
            .sign_schnorr(Message::from_digest_slice(digest).expect("digest is exactly 32 bytes"))
    }

    async fn pubkey(&self) -> <Server as Origin>::Container<XOnlyPublicKey> {
        self.kp.x_only_public_key().0
    }
}
