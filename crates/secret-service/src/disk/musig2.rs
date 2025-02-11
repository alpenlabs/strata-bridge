use std::future::Future;

use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::{PublicKey, SecretKey},
    FirstRound, KeyAggContext, LiftedSignature, SecNonceSpices, SecondRound,
};
use rand::{thread_rng, Rng};
use rkyv::{rancor, with::Map, Archive, Deserialize, Serialize};
use secret_service_proto::v1::traits::{
    Musig2SessionId, Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound, Origin, Server,
    SignerIdxOutOfBounds,
};
use secret_service_server::RoundPersister;
use sled::Tree;
use terrors::OneOf;

pub struct Ms2Signer {
    key: SecretKey,
}

impl Ms2Signer {
    pub fn new(key: SecretKey) -> Self {
        Self { key }
    }
}

impl Musig2Signer<Server, ServerFirstRound> for Ms2Signer {
    fn new_session(
        &self,
        ctx: KeyAggContext,
        signer_idx: usize,
    ) -> impl Future<Output = Result<ServerFirstRound, SignerIdxOutOfBounds>> + Send {
        async move {
            let nonce_seed = thread_rng().gen::<[u8; 32]>();
            let ordered_public_keys = ctx.pubkeys().iter().cloned().map(|p| p.into()).collect();
            let first_round = FirstRound::new(
                ctx,
                nonce_seed,
                signer_idx,
                SecNonceSpices::new().with_seckey(self.key.clone()),
            )
            .map_err(|e| SignerIdxOutOfBounds {
                index: e.index,
                n_signers: e.n_signers,
            })?;
            Ok(ServerFirstRound {
                first_round,
                ordered_public_keys,
                seckey: self.key.clone(),
            })
        }
    }
}

pub struct SledRoundPersist {
    first_rounds: Tree,
    second_rounds: Tree,
}

impl SledRoundPersist {
    pub fn new(first_rounds: Tree, second_rounds: Tree) -> Self {
        Self {
            first_rounds,
            second_rounds,
        }
    }
}

impl RoundPersister<ServerFirstRound, ServerSecondRound> for SledRoundPersist {
    type Error = OneOf<(rancor::Error, sled::Error)>;

    fn persist_first_round(
        &self,
        session_id: Musig2SessionId,
        first_round: &ServerFirstRound,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            let bytes = rkyv::to_bytes::<rancor::Error>(first_round).map_err(OneOf::new)?;
            self.first_rounds
                .insert(&session_id.to_be_bytes(), bytes.as_ref())
                .map_err(OneOf::new)?;
            self.first_rounds.flush_async().await.map_err(OneOf::new)?;
            Ok(())
        }
    }

    fn persist_second_round(
        &self,
        session_id: Musig2SessionId,
        second_round: &ServerSecondRound,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            let bytes = rkyv::to_bytes::<rancor::Error>(second_round).map_err(OneOf::new)?;
            self.second_rounds
                .insert(&session_id.to_be_bytes(), bytes.as_ref())
                .map_err(OneOf::new)?;
            self.second_rounds.flush_async().await.map_err(OneOf::new)?;
            Ok(())
        }
    }

    fn delete_first_round(
        &self,
        session_id: Musig2SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            self.first_rounds
                .remove(&session_id.to_be_bytes())
                .map_err(OneOf::new)?;
            self.first_rounds.flush_async().await.map_err(OneOf::new)?;
            Ok(())
        }
    }

    fn delete_second_round(
        &self,
        session_id: Musig2SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            self.second_rounds
                .remove(&session_id.to_be_bytes())
                .map_err(OneOf::new)?;
            self.second_rounds.flush_async().await.map_err(OneOf::new)?;
            Ok(())
        }
    }

    fn load_first_rounds(
        &self,
    ) -> impl Future<Output = Result<Vec<(Musig2SessionId, ServerFirstRound)>, Self::Error>> + Send
    {
        async move {
            Ok(self
                .first_rounds
                .iter()
                .map(|res| {
                    let (session_id_bytes, bytes) = res.map_err(OneOf::new)?;
                    let session_id = Musig2SessionId::from_be_bytes(
                        session_id_bytes
                            .as_ref()
                            .try_into()
                            .expect("valid session id"),
                    );
                    let first_round = rkyv::from_bytes::<ServerFirstRound, rancor::Error>(&bytes)
                        .map_err(OneOf::new)?;
                    Ok((session_id, first_round))
                })
                .collect::<Result<Vec<_>, Self::Error>>()?)
        }
    }

    fn load_second_rounds(
        &self,
    ) -> impl Future<Output = Result<Vec<(Musig2SessionId, ServerSecondRound)>, Self::Error>> + Send
    {
        async move {
            Ok(self
                .second_rounds
                .iter()
                .map(|res| {
                    let (session_id_bytes, bytes) = res.map_err(OneOf::new)?;
                    let session_id = Musig2SessionId::from_be_bytes(
                        session_id_bytes
                            .as_ref()
                            .try_into()
                            .expect("valid session id"),
                    );
                    let second_round = rkyv::from_bytes::<ServerSecondRound, rancor::Error>(&bytes)
                        .map_err(OneOf::new)?;
                    Ok((session_id, second_round))
                })
                .collect::<Result<Vec<_>, Self::Error>>()?)
        }
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub struct ServerFirstRound {
    first_round: FirstRound,
    #[rkyv(with = Map<musig2::rkyv_wrappers::PublicKey>)]
    ordered_public_keys: Vec<PublicKey>,
    #[rkyv(with = musig2::rkyv_wrappers::SecretKey)]
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

#[derive(Archive, Serialize, Deserialize)]
pub struct ServerSecondRound {
    second_round: SecondRound<[u8; 32]>,
    #[rkyv(with = Map<musig2::rkyv_wrappers::PublicKey>)]
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
