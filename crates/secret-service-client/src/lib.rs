use std::{
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bitcoin::Psbt;
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::{Error, PublicKey},
    AggNonce, LiftedSignature, PubNonce,
};
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
    rustls, ClientConfig, ConnectError, Connection, ConnectionError, Endpoint,
};
use rkyv::{deserialize, rancor};
use secret_service_proto::{
    v1::{
        traits::{
            Client, ClientError, Musig2SessionId, Musig2Signer, Musig2SignerFirstRound,
            Musig2SignerSecondRound, OperatorSigner, Origin, P2PSigner, SecretService, WotsSigner,
        },
        wire::{ClientMessage, ServerMessage},
    },
    wire::{
        ArchivedVersionedServerMessage, LengthUint, VersionedClientMessage, VersionedServerMessage,
        WireMessage,
    },
};
use terrors::OneOf;
use tokio::time::timeout;

#[derive(Clone)]
pub struct Config {
    server_addr: SocketAddr,
    server_hostname: String,
    local_addr: Option<SocketAddr>,
    tls_config: rustls::ClientConfig,
    timeout: Duration,
}

#[derive(Clone)]
pub struct SecretServiceClient {
    endpoint: Endpoint,
    config: Arc<Config>,
    conn: Connection,
}

impl SecretServiceClient {
    pub async fn new(
        config: Config,
    ) -> Result<
        Self,
        OneOf<(
            NoInitialCipherSuite,
            ConnectError,
            ConnectionError,
            io::Error,
        )>,
    > {
        let endpoint = Endpoint::client(
            config
                .local_addr
                .unwrap_or((Ipv4Addr::UNSPECIFIED, 0).into()),
        )
        .map_err(OneOf::new)?;

        let connecting = endpoint
            .connect_with(
                ClientConfig::new(Arc::new(
                    QuicClientConfig::try_from(config.tls_config.clone()).map_err(OneOf::new)?,
                )),
                config.server_addr,
                &config.server_hostname,
            )
            .map_err(OneOf::new)?;
        let conn = connecting.await.map_err(OneOf::new)?;

        Ok(SecretServiceClient {
            endpoint,
            config: Arc::new(config),
            conn,
        })
    }
}

impl SecretService<Client, Musig2FirstRound, Musig2SecondRound> for SecretServiceClient {
    type OperatorSigner = OperatorClient;

    type P2PSigner = P2PClient;

    type Musig2Signer = Musig2Client;

    type WotsSigner = WotsClient;

    fn operator_signer(&self) -> Self::OperatorSigner {
        OperatorClient {
            conn: self.conn.clone(),
            config: self.config.clone(),
        }
    }

    fn p2p_signer(&self) -> Self::P2PSigner {
        P2PClient {
            conn: self.conn.clone(),
            config: self.config.clone(),
        }
    }

    fn musig2_signer(&self) -> Self::Musig2Signer {
        Musig2Client {
            conn: self.conn.clone(),
            config: self.config.clone(),
        }
    }

    fn wots_signer(&self) -> Self::WotsSigner {
        WotsClient {
            conn: self.conn.clone(),
            config: self.config.clone(),
        }
    }
}

struct Musig2FirstRound {
    session_id: Musig2SessionId,
    connection: Connection,
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
                return Err(ClientError::ProtocolError(res));
            };
            PubNonce::from_bytes(&our_nonce).map_err(|_| ClientError::BadData)
        }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<Vec<PublicKey>>> + Send {
        async move {
            let msg = ClientMessage::Musig2FirstRoundHoldouts {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2FirstRoundHoldouts { pubkeys } = res else {
                return Err(ClientError::ProtocolError(res));
            };
            pubkeys
                .into_iter()
                .map(|pk| PublicKey::from_slice(&pk))
                .collect::<Result<Vec<PublicKey>, Error>>()
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
                return Err(ClientError::ProtocolError(res));
            };
            Ok(complete)
        }
    }

    fn receive_pub_nonce(
        &self,
        pubkey: PublicKey,
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
                return Err(ClientError::ProtocolError(res));
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
                hash,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2FirstRoundFinalize(maybe_err) = res else {
                return Err(ClientError::ProtocolError(res));
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

struct Musig2SecondRound {
    session_id: Musig2SessionId,
    connection: Connection,
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
                return Err(ClientError::ProtocolError(res));
            };
            AggNonce::from_bytes(&nonce).map_err(|_| ClientError::BadData)
        }
    }

    fn holdouts(
        &self,
    ) -> impl Future<Output = <Client as Origin>::Container<Vec<PublicKey>>> + Send {
        async move {
            let msg = ClientMessage::Musig2SecondRoundHoldouts {
                session_id: self.session_id,
            };
            let res = make_v1_req(&self.connection, msg, self.config.timeout).await?;
            let ServerMessage::Musig2SecondRoundHoldouts { pubkeys } = res else {
                return Err(ClientError::ProtocolError(res));
            };
            pubkeys
                .into_iter()
                .map(|pk| PublicKey::from_slice(&pk))
                .collect::<Result<Vec<PublicKey>, Error>>()
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
                return Err(ClientError::ProtocolError(res));
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
                return Err(ClientError::ProtocolError(res));
            };
            Ok(complete)
        }
    }

    fn receive_signature(
        &self,
        pubkey: PublicKey,
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
                return Err(ClientError::ProtocolError(res));
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
                return Err(ClientError::ProtocolError(res));
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

struct OperatorClient {
    conn: Connection,
    config: Arc<Config>,
}

impl OperatorSigner<Client> for OperatorClient {
    fn sign_psbt(
        &self,
        psbt: Psbt,
    ) -> impl Future<Output = <Client as Origin>::Container<Psbt>> + Send {
        async move {
            let msg = ClientMessage::OperatorSignPsbt {
                psbt: psbt.serialize(),
            };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::OperatorSignPsbt { psbt } = res else {
                return Err(ClientError::ProtocolError(res));
            };
            Psbt::deserialize(&psbt).map_err(|_| ClientError::BadData)
        }
    }
}

struct P2PClient {
    conn: Connection,
    config: Arc<Config>,
}

impl P2PSigner<Client> for P2PClient {
    fn sign_p2p(
        &self,
        hash: [u8; 32],
    ) -> impl Future<Output = <Client as Origin>::Container<[u8; 64]>> + Send {
        async move {
            let msg = ClientMessage::SignP2P { hash };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::SignP2P { sig } = res else {
                return Err(ClientError::ProtocolError(res));
            };
            Ok(sig)
        }
    }

    fn p2p_pubkey(&self) -> impl Future<Output = <Client as Origin>::Container<[u8; 33]>> + Send {
        async move {
            let msg = ClientMessage::P2PPubkey;
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::P2PPubkey { pubkey } = res else {
                return Err(ClientError::ProtocolError(res));
            };
            Ok(pubkey)
        }
    }
}

struct Musig2Client {
    conn: Connection,
    config: Arc<Config>,
}

impl Musig2Signer<Client, Musig2FirstRound> for Musig2Client {
    fn new_session(&self) -> impl Future<Output = Result<Musig2FirstRound, ClientError>> + Send {
        async move {
            let msg = ClientMessage::Musig2NewSession;
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::Musig2NewSession { session_id } = res else {
                return Err(ClientError::ProtocolError(res));
            };

            Ok(Musig2FirstRound {
                session_id,
                connection: self.conn.clone(),
                config: self.config.clone(),
            })
        }
    }
}

struct WotsClient {
    conn: Connection,
    config: Arc<Config>,
}

impl WotsSigner<Client> for WotsClient {
    fn get_key(
        &self,
        index: u64,
    ) -> impl Future<Output = <Client as Origin>::Container<[u8; 64]>> + Send {
        async move {
            let msg = ClientMessage::WotsGetKey { index };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::WotsGetKey { key } = res else {
                return Err(ClientError::ProtocolError(res));
            };
            Ok(key)
        }
    }
}

async fn make_v1_req(
    conn: &Connection,
    msg: ClientMessage,
    timeout_dur: Duration,
) -> Result<ServerMessage, ClientError> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(ClientError::ConnectionError)?;
    timeout(
        timeout_dur,
        tx.write_all(
            &VersionedClientMessage::V1(msg)
                .serialize()
                .map_err(ClientError::SerializationError)?,
        ),
    )
    .await
    .map_err(|_| ClientError::Timeout)?
    .map_err(ClientError::WriteError)?;

    let len_to_read = {
        let mut buf = [0; size_of::<LengthUint>()];
        timeout(timeout_dur, rx.read_exact(&mut buf))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(ClientError::ReadError)?;
        LengthUint::from_le_bytes(buf)
    };

    let mut buf = vec![0; len_to_read as usize];
    timeout(timeout_dur, rx.read_exact(&mut buf))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::ReadError)?;

    let archived = rkyv::access::<ArchivedVersionedServerMessage, rancor::Error>(&buf)
        .map_err(ClientError::DeserializationError)?;

    let VersionedServerMessage::V1(msg) =
        deserialize(archived).map_err(ClientError::DeserializationError)?;

    Ok(msg)
}
