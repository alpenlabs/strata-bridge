//! In-memory persistence for MuSig2's secret data.

use std::collections::BTreeMap;

use bitcoin::{
    bip32::Xpriv,
    hashes::Hash,
    key::{Keypair, Parity, TapTweak},
    TapNodeHash, Txid, XOnlyPublicKey,
};
use hkdf::Hkdf;
use make_buf::make_buf;
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::{schnorr::Signature, Message, SecretKey, SECP256K1},
    FirstRound, KeyAggContext, LiftedSignature, PartialSignature, PubNonce, SecNonceSpices,
    SecondRound,
};
use secret_service_proto::v1::traits::{
    Musig2SessionId, Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound, Origin,
    SchnorrSigner, Server, SignerIdxOutOfBounds,
};
use sha2::Sha256;
use strata_bridge_primitives::{scripts::taproot::TaprootWitness, secp::EvenSecretKey};

use super::paths::{MUSIG2_KEY_PATH, MUSIG2_NONCE_IKM_PATH};

/// Secret data for the MuSig2 signer.
#[derive(Debug)]
pub struct Ms2Signer {
    /// Operator's [`Keypair`].
    kp: Keypair,

    /// Initial key material to derive secret nonces.
    ikm: [u8; 32],
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
}

impl Musig2Signer<Server, ServerFirstRound> for Ms2Signer {
    async fn new_session(
        &self,
        _session_id: Musig2SessionId,
        ordered_pubkeys: Vec<XOnlyPublicKey>,
        witness: TaprootWitness,
        input_txid: Txid,
        input_vout: u32,
    ) -> Result<ServerFirstRound, SignerIdxOutOfBounds> {
        let my_pub_key = self.kp.x_only_public_key().0;
        let signer_index = ordered_pubkeys
            .iter()
            .position(|pk| pk == &my_pub_key)
            .ok_or(SignerIdxOutOfBounds {
                index: usize::MAX,
                n_signers: usize::MAX,
            })?;
        let mut ctx =
            KeyAggContext::new(ordered_pubkeys.iter().map(|pk| pk.public_key(Parity::Even)))
                .unwrap();

        match witness {
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

        let nonce_seed = {
            let info = make_buf! {
                (&input_txid.as_raw_hash().to_byte_array(), 32),
                (&input_vout.to_le_bytes(), 4)
            };
            let hk = Hkdf::<Sha256>::new(None, &self.ikm);
            let mut okm = [0u8; 32];
            hk.expand(&info, &mut okm)
                .expect("32 is a valid length for Sha256 to output");
            okm
        };

        let first_round = FirstRound::new(
            ctx,
            nonce_seed,
            signer_index,
            SecNonceSpices::new().with_seckey(self.kp.secret_key()),
        )
        .map_err(|e| SignerIdxOutOfBounds {
            index: e.index,
            n_signers: e.n_signers,
        })?;
        Ok(ServerFirstRound {
            first_round,
            ordered_public_keys: ordered_pubkeys,
            seckey: self.kp.secret_key(),
        })
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

/// First round of the MuSig2 protocol for the server.
#[allow(missing_debug_implementations)]
pub struct ServerFirstRound {
    /// The first round of the MuSig2 protocol.
    first_round: FirstRound,

    /// Ordered X-only public keys of the signers.
    ordered_public_keys: Vec<XOnlyPublicKey>,

    /// Operator's [`SecretKey`].
    seckey: SecretKey,
}

impl Musig2SignerFirstRound<Server, ServerSecondRound> for ServerFirstRound {
    async fn our_nonce(&self) -> <Server as Origin>::Container<musig2::PubNonce> {
        self.first_round.our_public_nonce()
    }

    async fn holdouts(&self) -> <Server as Origin>::Container<Vec<XOnlyPublicKey>> {
        self.first_round
            .holdouts()
            .iter()
            .map(|idx| self.ordered_public_keys[*idx])
            .collect()
    }

    async fn is_complete(&self) -> <Server as Origin>::Container<bool> {
        self.first_round.is_complete()
    }

    async fn receive_pub_nonces(
        &mut self,
        nonces: impl Iterator<Item = (XOnlyPublicKey, PubNonce)>,
    ) -> <Server as Origin>::Container<Result<(), BTreeMap<XOnlyPublicKey, RoundContributionError>>>
    {
        let mut errs = BTreeMap::new();
        for (pubkey, nonce) in nonces {
            let signer_idx = match self.ordered_public_keys.iter().position(|x| x == &pubkey) {
                Some(idx) => idx,
                None => {
                    errs.insert(pubkey, RoundContributionError::out_of_range(0, 0));
                    continue;
                }
            };
            if let Err(e) = self.first_round.receive_nonce(signer_idx, nonce) {
                errs.insert(pubkey, e.clone());
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    async fn finalize(
        self,
        hash: [u8; 32],
    ) -> <Server as Origin>::Container<Result<ServerSecondRound, RoundFinalizeError>> {
        self.first_round
            .finalize(self.seckey, hash)
            .map(|sr| ServerSecondRound {
                second_round: sr,
                ordered_public_keys: self.ordered_public_keys,
            })
    }
}

/// Second round of the MuSig2 protocol for the server.
#[allow(missing_debug_implementations)]
pub struct ServerSecondRound {
    /// The second round of the MuSig2 protocol.
    second_round: SecondRound<[u8; 32]>,

    /// Ordered X-only public keys of the signers.
    ordered_public_keys: Vec<XOnlyPublicKey>,
}

impl Musig2SignerSecondRound<Server> for ServerSecondRound {
    async fn agg_nonce(&self) -> <Server as Origin>::Container<musig2::AggNonce> {
        self.second_round.aggregated_nonce().clone()
    }

    async fn holdouts(&self) -> <Server as Origin>::Container<Vec<XOnlyPublicKey>> {
        self.second_round
            .holdouts()
            .iter()
            .map(|idx| self.ordered_public_keys[*idx])
            .collect()
    }

    async fn our_signature(&self) -> <Server as Origin>::Container<musig2::PartialSignature> {
        self.second_round.our_signature()
    }

    async fn is_complete(&self) -> <Server as Origin>::Container<bool> {
        self.second_round.is_complete()
    }

    async fn receive_signatures(
        &mut self,
        sigs: impl Iterator<Item = (XOnlyPublicKey, PartialSignature)>,
    ) -> <Server as Origin>::Container<Result<(), BTreeMap<XOnlyPublicKey, RoundContributionError>>>
    {
        let mut errs = BTreeMap::new();
        for (pubkey, sig) in sigs {
            let signer_idx = match self.ordered_public_keys.iter().position(|x| x == &pubkey) {
                Some(idx) => idx,
                None => {
                    errs.insert(pubkey, RoundContributionError::out_of_range(0, 0));
                    continue;
                }
            };
            if let Err(e) = self.second_round.receive_signature(signer_idx, sig) {
                errs.insert(pubkey, e.clone());
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    async fn finalize(
        self,
    ) -> <Server as Origin>::Container<Result<LiftedSignature, RoundFinalizeError>> {
        self.second_round.finalize()
    }
}
