pub mod bool_arr;
pub mod ms2sm;

use std::{
    future::Future,
    io,
    marker::{PhantomData, Sync},
    mem::MaybeUninit,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bitcoin::{secp256k1::PublicKey, Psbt};
use kanal::AsyncSender;
use ms2sm::Musig2SessionManager;
use musig2::{errors::RoundFinalizeError, LiftedSignature, PartialSignature, PubNonce};
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
        wire::{ArchivedClientMessage, ServerMessage},
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

pub fn run_server<SecondRound, FirstRound, Service>(
    c: Config,
    service: Arc<Service>,
) -> Result<ServerHandle, OneOf<(NoInitialCipherSuite, io::Error)>>
where
    SecondRound: Musig2SignerSecondRound<Server> + 'static,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound> + 'static,
    Service: SecretService<Server, SecondRound, FirstRound> + Sync + 'static,
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

async fn conn_handler<SecondRound, FirstRound, Service>(
    incoming: Incoming,
    service: Arc<Service>,
    musig2_sm: Arc<Mutex<Musig2SessionManager<FirstRound, SecondRound>>>,
) where
    SecondRound: Musig2SignerSecondRound<Server> + 'static,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound> + 'static,
    Service: SecretService<Server, SecondRound, FirstRound> + Sync + 'static,
{
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(e) => {
            warn!("accepting incoming conn failed: {e:?}");
            return;
        }
    };

    let mut req_id: usize = 0;
    let (err_tx, err_rx) = kanal::unbounded_async();

    tokio::spawn(
        async move {
            while let Ok(io_err) = err_rx.recv().await {
                match io_err {
                    IoError::WriteError(e) => {
                        warn!("write error: {e:?}");
                    }
                    IoError::ReadError(e) => {
                        warn!("read error: {e:?}");
                    }
                }
            }
        }
        .instrument(span!(Level::INFO, "conn-error-handler", cid = %conn.stable_id())),
    );

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
        let span = span!(Level::INFO, "stream", cid = %conn.stable_id(), rid = req_id);
        tokio::spawn(
            request_handler(tx, rx, service.clone(), musig2_sm.clone(), err_tx.clone())
                .instrument(span),
        );
    }
}

async fn request_handler<Service, SecondRound, FirstRound>(
    mut tx: SendStream,
    mut rx: RecvStream,
    service: Arc<Service>,
    musig2_sm: Arc<Mutex<Musig2SessionManager<FirstRound, SecondRound>>>,
    err_tx: AsyncSender<IoError>,
) where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    Service: SecretService<Server, SecondRound, FirstRound>,
{
    let len_to_read = {
        let mut buf = 0u16.to_le_bytes();
        if let Err(e) = rx.read_exact(&mut buf).await {
            let _ = err_tx.send(e.into()).await;
            return;
        }
        u16::from_le_bytes(buf)
    };

    let mut buf = vec![0u8; len_to_read as usize];
    if let Err(e) = rx.read_exact(&mut buf).await {
        let _ = err_tx.send(e.into()).await;
        return;
    }

    let msg = rkyv::access::<ArchivedVersionedClientMessage, Error>(&buf).unwrap();
    let res = match msg {
        // this would be a separate function but tokio would start whining because !Sync
        ArchivedVersionedClientMessage::V1(req) => match req {
            ArchivedClientMessage::OperatorSignPsbt { psbt } => {
                let psbt = Psbt::deserialize(&psbt).unwrap();
                let r = service.operator_signer().sign_psbt(psbt).await;
                ServerMessage::<Service, SecondRound, FirstRound>::OperatorSignPsbt(
                    r.map(|psbt| psbt.serialize()),
                )
            }

            ArchivedClientMessage::SignP2P { hash } => {
                let r = service.p2p_signer().sign_p2p(*hash).await;
                ServerMessage::<Service, SecondRound, FirstRound>::SignP2P(r)
            }

            ArchivedClientMessage::Musig2NewSession => {
                let first_round = service.musig2_signer().new_session().await;
                match musig2_sm.lock().await.new_session(first_round) {
                    Some(id) => {
                        ServerMessage::<Service, SecondRound, FirstRound>::Musig2NewSession(id)
                    }
                    None => ServerMessage::<Service, SecondRound, FirstRound>::OpaqueServerError,
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
                        ServerMessage::<Service, SecondRound, FirstRound>::Musig2FirstRoundOurNonce(
                            nonce,
                        )
                    }
                    _ => ServerMessage::<Service, SecondRound, FirstRound>::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundHoldouts { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                match r {
                    Ok(Some(first_round)) => {
                        ServerMessage::<Service, SecondRound, FirstRound>::Musig2FirstRoundHoldouts(
                            first_round
                                .holdouts()
                                .await
                                .iter()
                                .map(PublicKey::serialize)
                                .collect(),
                        )
                    }
                    _ => ServerMessage::<Service, SecondRound, FirstRound>::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundIsComplete { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                match r {
                    Ok(Some(first_round)) => ServerMessage::<
                        Service,
                        SecondRound,
                        FirstRound,
                    >::Musig2FirstRoundIsComplete(
                        first_round.is_complete().await
                    ),
                    _ => {
                        ServerMessage::<
                            Service,
                            SecondRound,
                            FirstRound,
                        >::InvalidClientMessage
                    }
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
                        ServerMessage::<
                            Service,
                            SecondRound,
                            FirstRound,
                        >::Musig2FirstRoundReceivePubNonce(r.err())
                    }
                    _ => ServerMessage::<Service, SecondRound, FirstRound>::InvalidClientMessage,
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
                        Ok(e) => ServerMessage::<
                            Service,
                            SecondRound,
                            FirstRound,
                        >::Musig2FirstRoundFinalize(Some(e)),
                        Err(e) => match e.as_enum() {
                            A(_not_in_first_round) => ServerMessage::<
                                Service,
                                SecondRound,
                                FirstRound,
                            >::InvalidClientMessage,
                            B(_out_of_range) => ServerMessage::<
                                Service,
                                SecondRound,
                                FirstRound,
                            >::InvalidClientMessage,
                            C(_other_refs_active) => ServerMessage::<
                                Service,
                                SecondRound,
                                FirstRound,
                            >::OpaqueServerError,
                        },
                    }
                } else {
                    ServerMessage::<Service, SecondRound, FirstRound>::Musig2FirstRoundFinalize(
                        None,
                    )
                }
            }

            ArchivedClientMessage::Musig2SecondRoundAggNonce { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => {
                        ServerMessage::<Service, SecondRound, FirstRound>::Musig2SecondRoundAggNonce(
                            sr.agg_nonce().await.serialize(),
                        )
                    }
                    _ => ServerMessage::<Service, SecondRound, FirstRound>::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundHoldouts { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => {
                        ServerMessage::<Service, SecondRound, FirstRound>::Musig2SecondRoundHoldouts(
                            sr.holdouts()
                                .await
                                .iter()
                                .map(PublicKey::serialize)
                                .collect(),
                        )
                    }
                    _ => ServerMessage::<Service, SecondRound, FirstRound>::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundOurSignature { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::<
                        Service,
                        SecondRound,
                        FirstRound,
                    >::Musig2SecondRoundOurSignature(
                        sr.our_signature().await.serialize()
                    ),
                    _ => {
                        ServerMessage::<
                            Service,
                            SecondRound,
                            FirstRound,
                        >::InvalidClientMessage
                    }
                }
            }
            ArchivedClientMessage::Musig2SecondRoundIsComplete { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::<
                        Service,
                        SecondRound,
                        FirstRound,
                    >::Musig2SecondRoundIsComplete(
                        sr.is_complete().await
                    ),
                    _ => {
                        ServerMessage::<
                            Service,
                            SecondRound,
                            FirstRound,
                        >::InvalidClientMessage
                    }
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
                        ServerMessage::<
                            Service,
                            SecondRound,
                            FirstRound,
                        >::Musig2SecondRoundReceiveSignature(r.err())
                    }
                    _ => ServerMessage::<Service, SecondRound, FirstRound>::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundFinalize { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .finalize_second_round(session_id.to_native() as usize)
                    .await;
                match r {
                    Ok(sig) => {
                        ServerMessage::<Service, SecondRound, FirstRound>::Musig2SecondRoundFinalize(
                            Ok(sig.serialize()).into(),
                        )
                    }
                    Err(e) => {
                        if let Ok(e) = e.narrow::<RoundFinalizeError, _>() {
                            ServerMessage::<
                                Service,
                                SecondRound,
                                FirstRound,
                            >::Musig2SecondRoundFinalize(Err(e).into())
                        } else {
                            ServerMessage::<Service, SecondRound, FirstRound>::InvalidClientMessage
                        }
                    }
                }
            }

            ArchivedClientMessage::WotsGetKey { index } => {
                let r = service.wots_signer().get_key(index.into()).await;
                ServerMessage::<Service, SecondRound, FirstRound>::WotsGetKey(r)
            }
        },
    };

    let byte_response = match rkyv::to_bytes::<rancor::Error>(&res) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to serialize response: {e:?}");
            let res = ServerMessage::<Service, SecondRound, FirstRound>::OpaqueServerError;
            if let Ok(bytes) = rkyv::to_bytes::<rancor::Error>(&res) {
                if let Err(e) = tx.write(&bytes).await {
                    let _ = err_tx.send(e.into()).await;
                }
            }
            return;
        }
    };
    if let Err(e) = tx.write(&byte_response).await {
        let _ = err_tx.send(IoError::WriteError(e)).await;
    }
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
