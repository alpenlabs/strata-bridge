//! MuSig2 signer client

use std::{future::Future, sync::Arc};

use bitcoin::{hashes::Hash, Txid, XOnlyPublicKey};
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    AggNonce, LiftedSignature, PubNonce,
};
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{
        Client, ClientError, Musig2SessionId, Musig2Signer, Musig2SignerFirstRound,
        Musig2SignerSecondRound, Origin, SignerIdxOutOfBounds,
    },
    wire::{ClientMessage, ServerMessage},
};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

use crate::{make_v1_req, Config};

/// MuSig2 client.
#[derive(Debug, Clone)]
pub struct Musig2Client {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl Musig2Client {
    /// Creates a new MuSig2 client with an existing QUIC connection and configuration.
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl Musig2Signer<Client, Musig2FirstRound> for Musig2Client {
    fn new_session(
        &self,
        pubkeys: Vec<XOnlyPublicKey>,
        witness: TaprootWitness,
        input_txid: Txid,
        input_vout: u32,
    ) -> impl Future<Output = Result<Result<Musig2FirstRound, SignerIdxOutOfBounds>, ClientError>> + Send
    {
        async move {
            let msg = ClientMessage::Musig2NewSession {
                pubkeys: pubkeys.into_iter().map(|pk| pk.serialize()).collect(),
                witness: witness.into(),
                input_txid: input_txid.to_byte_array(),
                input_vout,
            };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::Musig2NewSession(maybe_session_id) = res else {
                return Err(ClientError::WrongMessage(res));
            };

            Ok(match maybe_session_id {
                Ok(session_id) => Ok(Musig2FirstRound {
                    session_id,
                    connection: self.conn.clone(),
                    config: self.config.clone(),
                }),
                Err(e) => Err(e),
            })
        }
    }

    fn pubkey(&self) -> impl Future<Output = <Client as Origin>::Container<XOnlyPublicKey>> + Send {
        async move {
            let msg = ClientMessage::Musig2Pubkey;
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::Musig2Pubkey { pubkey } = res else {
                return Err(ClientError::WrongMessage(res));
            };

            XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::WrongMessage(res))
        }
    }
}

/// The first round of the MuSig2 protocol.
#[derive(Debug, Clone)]
pub struct Musig2FirstRound {
    /// The MuSig2 session ID.
    session_id: Musig2SessionId,

    /// The connection to the server.
    connection: Connection,

    /// The configuration for the client.
    config: Arc<Config>,
}

impl Musig2SignerFirstRound<Client, Musig2SecondRound> for Musig2FirstRound {
    fn our_nonce(&self) -> impl Future<Output = <Client as Origin>::Container<PubNonce>> + Send {
        async move {
            let msg = ClientMessage::Musig2FirstRoundOurNonce {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2FirstRoundOurNonce { our_nonce } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            PubNonce::from_bytes(&our_nonce).map_err(|_| ClientError::BadData)
        }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<Vec<XOnlyPublicKey>>> + Send {
        async move {
            let msg = ClientMessage::Musig2FirstRoundHoldouts {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2FirstRoundHoldouts { pubkeys } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            pubkeys
                .into_iter()
                .map(|pk| XOnlyPublicKey::from_slice(&pk))
                .collect::<Result<Vec<XOnlyPublicKey>, musig2::secp256k1::Error>>()
                .map_err(|_| ClientError::BadData)
        }
    }

    fn is_complete(&self) -> impl Future<Output = <Client as Origin>::Container<bool>> + Send {
        async move {
            let msg = ClientMessage::Musig2FirstRoundIsComplete {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2FirstRoundIsComplete { complete } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(complete)
        }
    }

    fn receive_pub_nonce(
        &mut self,
        pubkey: XOnlyPublicKey,
        pubnonce: PubNonce,
    ) -> impl Future<Output = <Client as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move {
            let msg = ClientMessage::Musig2FirstRoundReceivePubNonce {
                session_id: self.session_id,
                pubkey: pubkey.serialize(),
                pubnonce: pubnonce.serialize(),
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2FirstRoundReceivePubNonce(maybe_err) = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(maybe_err.map_or(Ok(()), Err))
        }
    }

    fn finalize(
        self,
        hash: [u8; 32],
    ) -> impl Future<
        Output = <Client as Origin>::Container<Result<Musig2SecondRound, RoundFinalizeError>>,
    > + Send {
        async move {
            let msg = ClientMessage::Musig2FirstRoundFinalize {
                session_id: self.session_id,
                digest: hash,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2FirstRoundFinalize(maybe_err) = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(match maybe_err {
                Some(e) => Err(e),
                None => Ok(Musig2SecondRound {
                    session_id: self.session_id,
                    connection: self.connection,
                    config: self.config,
                }),
            })
        }
    }
}

/// The second round of the MuSig2 protocol.
#[derive(Debug, Clone)]
pub struct Musig2SecondRound {
    /// The MuSig2 session ID.
    session_id: Musig2SessionId,

    /// The connection to the server.
    connection: Connection,

    /// The configuration for the client.
    config: Arc<Config>,
}

impl Musig2SignerSecondRound<Client> for Musig2SecondRound {
    fn agg_nonce(&self) -> impl Future<Output = <Client as Origin>::Container<AggNonce>> + Send {
        async move {
            let msg = ClientMessage::Musig2SecondRoundAggNonce {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2SecondRoundAggNonce { nonce } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            AggNonce::from_bytes(&nonce).map_err(|_| ClientError::BadData)
        }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<Vec<XOnlyPublicKey>>> + Send {
        async move {
            let msg = ClientMessage::Musig2SecondRoundHoldouts {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2SecondRoundHoldouts { pubkeys } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            pubkeys
                .into_iter()
                .map(|pk| XOnlyPublicKey::from_slice(&pk))
                .collect::<Result<Vec<XOnlyPublicKey>, musig2::secp256k1::Error>>()
                .map_err(|_| ClientError::BadData)
        }
    }

    fn our_signature(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<musig2::PartialSignature>> + Send {
        async move {
            let msg = ClientMessage::Musig2SecondRoundOurSignature {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2SecondRoundOurSignature { sig } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            musig2::PartialSignature::from_slice(&sig).map_err(|_| ClientError::BadData)
        }
    }

    fn is_complete(&self) -> impl Future<Output = <Client as Origin>::Container<bool>> + Send {
        async move {
            let msg = ClientMessage::Musig2SecondRoundIsComplete {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2SecondRoundIsComplete { complete } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(complete)
        }
    }

    fn receive_signature(
        &mut self,
        pubkey: XOnlyPublicKey,
        signature: musig2::PartialSignature,
    ) -> impl Future<Output = <Client as Origin>::Container<Result<(), RoundContributionError>>> + Send
    {
        async move {
            let msg = ClientMessage::Musig2SecondRoundReceiveSignature {
                session_id: self.session_id,
                pubkey: pubkey.serialize(),
                signature: signature.serialize(),
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2SecondRoundReceiveSignature(maybe_err) = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(maybe_err.map_or(Ok(()), Err))
        }
    }

    fn finalize(
        self,
    ) -> impl Future<
        Output = <Client as Origin>::Container<Result<musig2::LiftedSignature, RoundFinalizeError>>,
    > + Send {
        async move {
            let msg = ClientMessage::Musig2SecondRoundFinalize {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2SecondRoundFinalize(res) = res else {
                return Err(ClientError::WrongMessage(res));
            };
            let res: Result<_, _> = res.into();
            Ok(match res {
                Ok(sig) => {
                    let sig =
                        LiftedSignature::from_bytes(&sig).map_err(|_| ClientError::BadData)?;
                    Ok(sig)
                }
                Err(e) => Err(e),
            })
        }
    }
}
