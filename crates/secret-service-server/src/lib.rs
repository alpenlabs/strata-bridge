pub mod bool_arr;
pub mod ms2sm;

use std::{
    future::Future,
    io,
    marker::Sync,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bitcoin::{secp256k1::PublicKey, Psbt};
use kanal::AsyncSender;
use ms2sm::Musig2SessionManager;
use musig2::{errors::RoundFinalizeError, PartialSignature, PubNonce};
pub use quinn::rustls;
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicServerConfig},
    ConnectionError, Endpoint, Incoming, ReadExactError, RecvStream, SendStream, ServerConfig,
    WriteError,
};
use rkyv::rancor::{self, Error};
use secret_service_proto::{
    v1::{
        traits::{
            Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound, OperatorSigner,
            P2PSigner, SecretService, Server, WotsSigner,
        },
        wire::{ArchivedClientMessage, ServerMessage, WireMessage},
    },
    wire::ArchivedVersionedClientMessage,
};
use terrors::OneOf;
use tokio::{
    sync::Mutex,
    task::{JoinError, JoinHandle},
};
use tracing::{error, span, warn, Instrument, Level};

pub struct Config {
    addr: SocketAddr,
    connection_limit: Option<usize>,
    tls_config: rustls::ServerConfig,
}

pub struct ServerHandle {
    main: JoinHandle<()>,
}

impl Future for ServerHandle {
    type Output = Result<(), JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().main).poll(cx)
    }
}

pub fn run_server<FirstRound, SecondRound, Service>(
    c: Config,
    service: Arc<Service>,
) -> Result<ServerHandle, OneOf<(NoInitialCipherSuite, io::Error)>>
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound> + 'static,
    SecondRound: Musig2SignerSecondRound<Server> + 'static,
    Service: SecretService<Server, FirstRound, SecondRound> + Sync + 'static,
{
    let quic_server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(c.tls_config).map_err(OneOf::new)?,
    ));
    let endpoint = Endpoint::server(quic_server_config, c.addr).map_err(OneOf::new)?;
    let main_task = async move {
        let musig2_sm = Arc::new(Mutex::new(
            Musig2SessionManager::<FirstRound, SecondRound>::default(),
        ));
        while let Some(incoming) = endpoint.accept().await {
            let span = span!(Level::INFO,
                "connection",
                cid = %incoming.orig_dst_cid(),
                remote = %incoming.remote_address(),
                remote_validated = %incoming.remote_address_validated()
            );
            if matches!(c.connection_limit, Some(n) if endpoint.open_connections() >= n) {
                incoming.refuse();
            } else {
                tokio::spawn(
                    conn_handler(incoming, service.clone(), musig2_sm.clone()).instrument(span),
                );
            }
        }
    };
    let handle = tokio::spawn(main_task);
    Ok(ServerHandle { main: handle })
}

async fn conn_handler<FirstRound, SecondRound, Service>(
    incoming: Incoming,
    service: Arc<Service>,
    musig2_sm: Arc<Mutex<Musig2SessionManager<FirstRound, SecondRound>>>,
) where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound> + 'static,
    SecondRound: Musig2SignerSecondRound<Server> + 'static,
    Service: SecretService<Server, FirstRound, SecondRound> + Sync + 'static,
{
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(e) => {
            warn!("accepting incoming conn failed: {e:?}");
            return;
        }
    };

    let mut req_id: usize = 0;
    loop {
        let (tx, rx) = match conn.accept_bi().await {
            Ok(txers) => txers,
            Err(ConnectionError::ApplicationClosed(_)) => return,
            Err(e) => {
                warn!("accepting incoming stream failed: {e:?}");
                continue;
            }
        };
        req_id = req_id.wrapping_add(1);
        let handler_span =
            span!(Level::INFO, "request handler", cid = %conn.stable_id(), rid = req_id);
        let manager_span =
            span!(Level::INFO, "request manager", cid = %conn.stable_id(), rid = req_id);
        tokio::spawn(
            request_manager(
                tx,
                tokio::spawn(
                    request_handler(rx, service.clone(), musig2_sm.clone())
                        .instrument(handler_span),
                ),
            )
            .instrument(manager_span),
        );
    }
}

async fn request_manager<Service, FirstRound, SecondRound>(
    mut tx: SendStream,
    handler: JoinHandle<Result<ServerMessage<Service, FirstRound, SecondRound>, ReadExactError>>,
) where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    SecondRound: Musig2SignerSecondRound<Server>,
    Service: SecretService<Server, FirstRound, SecondRound>,
{
    let handler_res = match handler.await {
        Ok(r) => r,
        Err(e) => {
            error!("request handler failed: {e:?}");
            return;
        }
    };

    match handler_res {
        Ok(msg) => {
            let byte_response = match WireMessage::serialize(&msg) {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to serialize response: {e:?}");
                    return;
                }
            };
            if let Err(e) = tx.write_all(&byte_response).await {
                warn!("failed to send response: {e:?}");
            }
        }
        Err(e) => warn!("handler failed to read: {e:?}"),
    }
}

async fn request_handler<Service, FirstRound, SecondRound>(
    mut rx: RecvStream,
    service: Arc<Service>,
    musig2_sm: Arc<Mutex<Musig2SessionManager<FirstRound, SecondRound>>>,
) -> Result<ServerMessage<Service, FirstRound, SecondRound>, ReadExactError>
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    SecondRound: Musig2SignerSecondRound<Server>,
    Service: SecretService<Server, FirstRound, SecondRound>,
{
    let len_to_read = {
        let mut buf = 0u16.to_le_bytes();
        rx.read_exact(&mut buf).await?;
        u16::from_le_bytes(buf)
    };

    let mut buf = vec![0u8; len_to_read as usize];
    rx.read_exact(&mut buf).await?;

    let msg = rkyv::access::<ArchivedVersionedClientMessage, Error>(&buf).unwrap();
    Ok(match msg {
        // this would be a separate function but tokio would start whining because !Sync
        ArchivedVersionedClientMessage::V1(req) => match req {
            ArchivedClientMessage::OperatorSignPsbt { psbt } => {
                let psbt = Psbt::deserialize(&psbt).unwrap();
                let r = service.operator_signer().sign_psbt(psbt).await;
                ServerMessage::OperatorSignPsbt(r.map(|psbt| psbt.serialize()))
            }

            ArchivedClientMessage::SignP2P { hash } => {
                let r = service.p2p_signer().sign_p2p(*hash).await;
                ServerMessage::SignP2P(r)
            }

            ArchivedClientMessage::Musig2NewSession => {
                let first_round = service.musig2_signer().new_session().await;
                match musig2_sm.lock().await.new_session(first_round) {
                    Some(id) => ServerMessage::Musig2NewSession(id),
                    None => ServerMessage::OpaqueServerError,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundOurNonce { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                match r {
                    Ok(Some(first_round)) => {
                        let nonce = first_round.our_nonce().await.serialize();
                        ServerMessage::Musig2FirstRoundOurNonce(nonce)
                    }
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundHoldouts { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                match r {
                    Ok(Some(first_round)) => ServerMessage::Musig2FirstRoundHoldouts(
                        first_round
                            .holdouts()
                            .await
                            .iter()
                            .map(PublicKey::serialize)
                            .collect(),
                    ),
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundIsComplete { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                match r {
                    Ok(Some(first_round)) => {
                        ServerMessage::Musig2FirstRoundIsComplete(first_round.is_complete().await)
                    }
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundReceivePubNonce {
                session_id,
                pubkey,
                pubnonce,
            } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                let pubkey = PublicKey::from_slice(pubkey);
                let pubnonce = PubNonce::from_bytes(pubnonce);
                match (r, pubkey, pubnonce) {
                    (Ok(Some(first_round)), Ok(pubkey), Ok(pubnonce)) => {
                        let r = first_round.receive_pub_nonce(pubkey, pubnonce).await;
                        ServerMessage::Musig2FirstRoundReceivePubNonce(r.err())
                    }
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundFinalize { session_id, hash } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .transition_first_to_second_round(session_id.to_native() as usize, *hash)
                    .await;

                if let Err(e) = r {
                    use terrors::E3::*;
                    match e.narrow::<RoundFinalizeError, _>() {
                        Ok(e) => ServerMessage::Musig2FirstRoundFinalize(Some(e)),
                        Err(e) => match e.as_enum() {
                            A(_not_in_first_round) => ServerMessage::InvalidClientMessage,
                            B(_out_of_range) => ServerMessage::InvalidClientMessage,
                            C(_other_refs_active) => ServerMessage::OpaqueServerError,
                        },
                    }
                } else {
                    ServerMessage::Musig2FirstRoundFinalize(None)
                }
            }

            ArchivedClientMessage::Musig2SecondRoundAggNonce { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => {
                        ServerMessage::Musig2SecondRoundAggNonce(sr.agg_nonce().await.serialize())
                    }
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundHoldouts { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::Musig2SecondRoundHoldouts(
                        sr.holdouts()
                            .await
                            .iter()
                            .map(PublicKey::serialize)
                            .collect(),
                    ),
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundOurSignature { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::Musig2SecondRoundOurSignature(
                        sr.our_signature().await.serialize(),
                    ),
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundIsComplete { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => {
                        ServerMessage::Musig2SecondRoundIsComplete(sr.is_complete().await)
                    }
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundReceiveSignature {
                session_id,
                pubkey,
                signature,
            } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);
                let pubkey = PublicKey::from_slice(pubkey);
                let signature = PartialSignature::from_slice(signature);
                match (sr, pubkey, signature) {
                    (Ok(Some(sr)), Ok(pubkey), Ok(signature)) => {
                        let r = sr.receive_signature(pubkey, signature).await;
                        ServerMessage::Musig2SecondRoundReceiveSignature(r.err())
                    }
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundFinalize { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .finalize_second_round(session_id.to_native() as usize)
                    .await;
                match r {
                    Ok(sig) => ServerMessage::Musig2SecondRoundFinalize(Ok(sig.serialize()).into()),
                    Err(e) => {
                        if let Ok(e) = e.narrow::<RoundFinalizeError, _>() {
                            ServerMessage::Musig2SecondRoundFinalize(Err(e).into())
                        } else {
                            ServerMessage::InvalidClientMessage
                        }
                    }
                }
            }

            ArchivedClientMessage::WotsGetKey { index } => {
                let r = service.wots_signer().get_key(index.into()).await;
                ServerMessage::WotsGetKey(r)
            }
        },
    })
}

enum IoError {
    WriteError(WriteError),
    ReadError(ReadExactError),
}

impl From<WriteError> for IoError {
    fn from(e: WriteError) -> Self {
        IoError::WriteError(e)
    }
}

impl From<ReadExactError> for IoError {
    fn from(e: ReadExactError) -> Self {
        IoError::ReadError(e)
    }
}
