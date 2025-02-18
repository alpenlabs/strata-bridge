use std::future::Future;

use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    hashes::Hash,
    key::Keypair,
    Txid,
};
use hkdf::Hkdf;
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::{PublicKey, SecretKey, SECP256K1},
    FirstRound, KeyAggContext, LiftedSignature, SecNonceSpices, SecondRound,
};
use rand::{thread_rng, Rng};
use secret_service_proto::v1::traits::{
    Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound, Origin, Server,
    SignerIdxOutOfBounds,
};
use sha2::Sha256;
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

pub struct Ms2Signer {
    kp: Keypair,
    ikm: [u8; 32],
}

impl Ms2Signer {
    pub fn new(base: &Xpriv) -> Self {
        let key = base
            .derive_priv(
                SECP256K1,
                &[
                    ChildNumber::from_hardened_idx(20).unwrap(),
                    ChildNumber::from_hardened_idx(101).unwrap(),
                ],
            )
            .expect("valid key")
            .private_key;
        let ikm = base
            .derive_priv(
                SECP256K1,
                &[
                    ChildNumber::from_hardened_idx(666).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                ],
            )
            .expect("valid child")
            .private_key
            .secret_bytes();
        Self {
            kp: Keypair::from_secret_key(SECP256K1, &key),
            ikm,
        }
    }
}

impl Musig2Signer<Server, ServerFirstRound> for Ms2Signer {
    fn new_session(
        &self,
        mut pubkeys: Vec<PublicKey>,
        witness: TaprootWitness,
        input_txid: Txid,
        input_vout: u32,
    ) -> impl Future<Output = Result<ServerFirstRound, SignerIdxOutOfBounds>> + Send {
        async move {
            if !pubkeys.contains(&self.kp.public_key()) {
                pubkeys.push(self.kp.public_key());
            }
            pubkeys.sort();
            let signer_index = pubkeys
                .iter()
                .position(|pk| pk == &self.kp.public_key())
                .unwrap();
            let mut ctx = KeyAggContext::new(pubkeys.clone()).unwrap();

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
                let info = {
                    let mut buf = [0; 36];
                    buf[0..32].copy_from_slice(&input_txid.as_raw_hash().to_byte_array());
                    buf[32..36].copy_from_slice(&input_vout.to_le_bytes());
                    buf
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
                ordered_public_keys: pubkeys,
                seckey: self.kp.secret_key(),
            })
        }
    }

    fn pubkey(&self) -> impl Future<Output = <Server as Origin>::Container<PublicKey>> + Send {
        async move { self.kp.public_key() }
    }
}

pub struct ServerFirstRound {
    first_round: FirstRound,
    ordered_public_keys: Vec<PublicKey>,
    seckey: SecretKey,
}

impl Musig2SignerFirstRound<Server, ServerSecondRound> for ServerFirstRound {
    fn our_nonce(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::PubNonce>> + Send {
        async move { self.first_round.our_public_nonce() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<Vec<PublicKey>>> + Send {
        async move {
            self.first_round
                .holdouts()
                .iter()
                .map(|idx| self.ordered_public_keys[*idx])
                .collect()
        }
    }

    fn is_complete(&self) -> impl Future<Output = <Server as Origin>::Container<bool>> + Send {
        async move { self.first_round.is_complete() }
    }

    fn receive_pub_nonce(
        &mut self,
        pubkey: PublicKey,
        pubnonce: musig2::PubNonce,
    ) -> impl Future<Output = <Server as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move {
            let signer_idx = self
                .ordered_public_keys
                .iter()
                .position(|x| x == &pubkey)
                .ok_or(RoundContributionError::out_of_range(0, 0))?;
            self.first_round.receive_nonce(signer_idx, pubnonce)
        }
    }

    fn finalize(
        self,
        hash: [u8; 32],
    ) -> impl Future<
        Output = <Server as Origin>::Container<Result<ServerSecondRound, RoundFinalizeError>>,
    > + Send {
        async move {
            self.first_round
                .finalize(self.seckey, hash)
                .map(|sr| ServerSecondRound {
                    second_round: sr,
                    ordered_public_keys: self.ordered_public_keys,
                })
        }
    }
}

pub struct ServerSecondRound {
    second_round: SecondRound<[u8; 32]>,
    ordered_public_keys: Vec<PublicKey>,
}

impl Musig2SignerSecondRound<Server> for ServerSecondRound {
    fn agg_nonce(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::AggNonce>> + Send {
        async move { self.second_round.aggregated_nonce().clone() }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<Vec<PublicKey>>> + Send {
        async move {
            self.second_round
                .holdouts()
                .into_iter()
                .map(|idx| self.ordered_public_keys[*idx])
                .collect()
        }
    }

    fn our_signature(
        &self,
    ) -> impl Future<Output = <Server as Origin>::Container<musig2::PartialSignature>> + Send {
        async move { self.second_round.our_signature() }
    }

    fn is_complete(&self) -> impl Future<Output = <Server as Origin>::Container<bool>> + Send {
        async move { self.second_round.is_complete() }
    }

    fn receive_signature(
        &mut self,
        pubkey: PublicKey,
        signature: musig2::PartialSignature,
    ) -> impl Future<Output = <Server as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move {
            let signer_idx = self
                .ordered_public_keys
                .iter()
                .position(|x| x == &pubkey)
                .ok_or(RoundContributionError::out_of_range(0, 0))?;
            self.second_round.receive_signature(signer_idx, signature)
        }
    }

    fn finalize(
        self,
    ) -> impl Future<
        Output = <Server as Origin>::Container<Result<LiftedSignature, RoundFinalizeError>>,
    > + Send {
        async move { self.second_round.finalize() }
    }
}
