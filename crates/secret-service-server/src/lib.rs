pub mod bool_arr;
pub mod ms2sm;

use std::{
    fmt::Debug,
    future::Future,
    io,
    marker::Sync,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bitcoin::{hashes::Hash, secp256k1::PublicKey, Txid};
use ms2sm::Musig2SessionManager;
use musig2::{errors::RoundFinalizeError, KeyAggContext, PartialSignature, PubNonce};
pub use quinn::rustls;
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicServerConfig},
    ConnectionError, Endpoint, Incoming, ReadExactError, RecvStream, SendStream, ServerConfig,
};
use rkyv::{
    deserialize,
    rancor::{self, Error},
};
use secret_service_proto::{
    v1::{
        traits::{
            Musig2SessionId, Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound,
            OperatorSigner, P2PSigner, SecretService, Server, StakeChainPreimages, WotsSigner,
        },
        wire::{ArchivedClientMessage, ServerMessage},
    },
    wire::{ArchivedVersionedClientMessage, LengthUint, VersionedServerMessage, WireMessage},
};
use terrors::OneOf;
use tokio::{
    sync::Mutex,
    task::{JoinError, JoinHandle},
};
use tracing::{error, span, warn, Instrument, Level};

pub struct Config {
    pub addr: SocketAddr,
    pub connection_limit: Option<usize>,
    pub tls_config: rustls::ServerConfig,
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

pub fn run_server<FirstRound, SecondRound, Service, Persister>(
    c: Config,
    service: Arc<Service>,
    round_persister: Arc<Persister>,
) -> Result<ServerHandle, OneOf<(NoInitialCipherSuite, io::Error)>>
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound> + 'static,
    SecondRound: Musig2SignerSecondRound<Server> + 'static,
    Service: SecretService<Server, FirstRound, SecondRound> + Sync + 'static,
    Persister: RoundPersister<FirstRound, SecondRound> + Send + Sync + 'static,
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
                    conn_handler(
                        incoming,
                        service.clone(),
                        round_persister.clone(),
                        musig2_sm.clone(),
                    )
                    .instrument(span),
                );
            }
        }
    };
    let handle = tokio::spawn(main_task);
    Ok(ServerHandle { main: handle })
}

async fn conn_handler<FirstRound, SecondRound, Service, Persister>(
    incoming: Incoming,
    service: Arc<Service>,
    round_persister: Arc<Persister>,
    musig2_sm: Arc<Mutex<Musig2SessionManager<FirstRound, SecondRound>>>,
) where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound> + 'static,
    SecondRound: Musig2SignerSecondRound<Server> + 'static,
    Service: SecretService<Server, FirstRound, SecondRound> + Sync + 'static,
    Persister: RoundPersister<FirstRound, SecondRound> + Send + Sync + 'static,
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
                    request_handler(
                        rx,
                        service.clone(),
                        round_persister.clone(),
                        musig2_sm.clone(),
                    )
                    .instrument(handler_span),
                ),
            )
            .instrument(manager_span),
        );
    }
}

async fn request_manager(
    mut tx: SendStream,
    handler: JoinHandle<Result<ServerMessage, ReadExactError>>,
) {
    let handler_res = match handler.await {
        Ok(r) => r,
        Err(e) => {
            error!("request handler failed: {e:?}");
            return;
        }
    };

    match handler_res {
        Ok(msg) => {
            let byte_response = match WireMessage::serialize(&VersionedServerMessage::V1(msg)) {
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

async fn request_handler<Service, FirstRound, SecondRound, Persister>(
    mut rx: RecvStream,
    service: Arc<Service>,
    round_persister: Arc<Persister>,
    musig2_sm: Arc<Mutex<Musig2SessionManager<FirstRound, SecondRound>>>,
) -> Result<ServerMessage, ReadExactError>
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    SecondRound: Musig2SignerSecondRound<Server>,
    Service: SecretService<Server, FirstRound, SecondRound>,
    Persister: RoundPersister<FirstRound, SecondRound> + Send + Sync + 'static,
{
    let len_to_read = {
        let mut buf = [0; size_of::<LengthUint>()];
        rx.read_exact(&mut buf).await?;
        LengthUint::from_le_bytes(buf)
    };

    let mut buf = vec![0u8; len_to_read as usize];
    rx.read_exact(&mut buf).await?;

    let msg = rkyv::access::<ArchivedVersionedClientMessage, Error>(&buf).unwrap();
    Ok(match msg {
        // this would be a separate function but tokio would start whining because !Sync
        ArchivedVersionedClientMessage::V1(req) => match req {
            ArchivedClientMessage::OperatorSign { digest } => {
                let sig = service.operator_signer().sign(digest).await;
                ServerMessage::OperatorSignPsbt {
                    sig: sig.serialize(),
                }
            }

            ArchivedClientMessage::OperatorPubkey => {
                let pubkey = service.operator_signer().pubkey().await;
                ServerMessage::OperatorPubkey {
                    pubkey: pubkey.serialize(),
                }
            }

            ArchivedClientMessage::P2PSign { digest } => {
                let sig = service.p2p_signer().sign(digest).await;
                ServerMessage::SignP2P {
                    sig: sig.serialize(),
                }
            }

            ArchivedClientMessage::P2PPubkey => {
                let pubkey = service.p2p_signer().pubkey().await;
                ServerMessage::P2PPubkey {
                    pubkey: pubkey.serialize(),
                }
            }

            ArchivedClientMessage::Musig2NewSession { ctx, signer_idx } => 'block: {
                let signer = service.musig2_signer();
                let Ok(ctx) = deserialize::<KeyAggContext, rancor::Error>(ctx) else {
                    break 'block ServerMessage::InvalidClientMessage;
                };
                let first_round = match signer
                    .new_session(ctx, signer_idx.to_native() as usize)
                    .await
                {
                    Ok(fr) => fr,
                    Err(e) => break 'block ServerMessage::Musig2NewSession(Err(e)),
                };
                let mut sm = musig2_sm.lock().await;

                let Ok(write_perm) = sm.new_session(first_round) else {
                    break 'block ServerMessage::OpaqueServerError;
                };

                if let Err(e) = round_persister
                    .persist_first_round(write_perm.session_id(), &*write_perm.value().await)
                    .await
                {
                    error!("failed to persist first round: {e:?}");
                    break 'block ServerMessage::OpaqueServerError;
                }

                ServerMessage::Musig2NewSession(Ok(write_perm.session_id()))
            }
            ArchivedClientMessage::Musig2FirstRoundOurNonce { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                match r {
                    Ok(Some(first_round)) => {
                        let our_nonce = first_round.lock().await.our_nonce().await.serialize();
                        ServerMessage::Musig2FirstRoundOurNonce { our_nonce }
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
                    Ok(Some(first_round)) => ServerMessage::Musig2FirstRoundHoldouts {
                        pubkeys: first_round
                            .lock()
                            .await
                            .holdouts()
                            .await
                            .iter()
                            .map(PublicKey::serialize)
                            .collect(),
                    },
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundIsComplete { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .first_round(session_id.to_native() as usize);
                match r {
                    Ok(Some(first_round)) => ServerMessage::Musig2FirstRoundIsComplete {
                        complete: first_round.lock().await.is_complete().await,
                    },
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundReceivePubNonce {
                session_id,
                pubkey,
                pubnonce,
            } => {
                let session_id = session_id.to_native() as usize;
                let r = musig2_sm.lock().await.first_round(session_id);
                let pubkey = PublicKey::from_slice(pubkey);
                let pubnonce = PubNonce::from_bytes(pubnonce);
                match (r, pubkey, pubnonce) {
                    (Ok(Some(first_round)), Ok(pubkey), Ok(pubnonce)) => {
                        let mut fr = first_round.lock().await;
                        let r = fr.receive_pub_nonce(pubkey, pubnonce).await;
                        if let Err(e) = round_persister.persist_first_round(session_id, &*fr).await
                        {
                            error!("failed to persist first round: {e:?}");
                            ServerMessage::OpaqueServerError
                        } else {
                            ServerMessage::Musig2FirstRoundReceivePubNonce(r.err())
                        }
                    }
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2FirstRoundFinalize { session_id, hash } => 'block: {
                let session_id = session_id.to_native() as usize;
                let mut sm = musig2_sm.lock().await;
                let r = sm.transition_first_to_second_round(session_id, *hash).await;

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
                    let mutex = sm
                        .second_round(session_id)
                        .expect("in range")
                        .expect("transitioned to second round");
                    let sr = mutex.lock().await;
                    if let Err(e) = round_persister.persist_second_round(session_id, &sr).await {
                        error!("failed to persist second round: {e:?}");
                        break 'block ServerMessage::OpaqueServerError;
                    }
                    if let Err(e) = round_persister.delete_first_round(session_id).await {
                        error!("failed to delete first round: {e:?}");
                        break 'block ServerMessage::OpaqueServerError;
                    }
                    ServerMessage::Musig2FirstRoundFinalize(None)
                }
            }

            ArchivedClientMessage::Musig2SecondRoundAggNonce { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::Musig2SecondRoundAggNonce {
                        nonce: sr.lock().await.agg_nonce().await.serialize(),
                    },
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundHoldouts { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::Musig2SecondRoundHoldouts {
                        pubkeys: sr
                            .lock()
                            .await
                            .holdouts()
                            .await
                            .iter()
                            .map(PublicKey::serialize)
                            .collect(),
                    },
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundOurSignature { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::Musig2SecondRoundOurSignature {
                        sig: sr.lock().await.our_signature().await.serialize(),
                    },
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundIsComplete { session_id } => {
                let sr = musig2_sm
                    .lock()
                    .await
                    .second_round(session_id.to_native() as usize);

                match sr {
                    Ok(Some(sr)) => ServerMessage::Musig2SecondRoundIsComplete {
                        complete: sr.lock().await.is_complete().await,
                    },
                    _ => ServerMessage::InvalidClientMessage,
                }
            }
            ArchivedClientMessage::Musig2SecondRoundReceiveSignature {
                session_id,
                pubkey,
                signature,
            } => {
                let session_id = session_id.to_native() as usize;
                let sr = musig2_sm.lock().await.second_round(session_id);
                let pubkey = PublicKey::from_slice(pubkey);
                let signature = PartialSignature::from_slice(signature);
                match (sr, pubkey, signature) {
                    (Ok(Some(sr)), Ok(pubkey), Ok(signature)) => {
                        let mut sr = sr.lock().await;
                        let r = sr.receive_signature(pubkey, signature).await;
                        if let Err(e) = round_persister.persist_second_round(session_id, &sr).await
                        {
                            error!("failed to persist second round: {e:?}");
                            ServerMessage::OpaqueServerError
                        } else {
                            ServerMessage::Musig2SecondRoundReceiveSignature(r.err())
                        }
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
                match r.map_err(|e| e.narrow::<RoundFinalizeError, _>()) {
                    Ok(sig) => ServerMessage::Musig2SecondRoundFinalize(Ok(sig.serialize()).into()),
                    Err(Ok(e)) => ServerMessage::Musig2SecondRoundFinalize(Err(e).into()),
                    Err(Err(_e)) => ServerMessage::InvalidClientMessage,
                }
            }

            ArchivedClientMessage::WotsGetKey { index, txid } => {
                let txid = Txid::from_slice(txid).expect("correct length");
                let key = service.wots_signer().get_key(index.into(), txid).await;
                ServerMessage::WotsGetKey { key }
            }

            ArchivedClientMessage::StakeChainGetPreimage { deposit_idx } => {
                let preimg = service.stake_chain().get_preimg(deposit_idx.into()).await;
                ServerMessage::StakeChainGetPreimage { preimg }
            }
        },
    })
}

pub trait RoundPersister<FirstRound, SecondRound>
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    SecondRound: Musig2SignerSecondRound<Server>,
{
    type Error: Debug;

    fn persist_first_round(
        &self,
        session_id: Musig2SessionId,
        first_round: &FirstRound,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn persist_second_round(
        &self,
        session_id: Musig2SessionId,
        second_round: &SecondRound,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn delete_first_round(
        &self,
        session_id: Musig2SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn delete_second_round(
        &self,
        session_id: Musig2SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn load_first_rounds(
        &self,
    ) -> impl Future<Output = Result<Vec<(Musig2SessionId, FirstRound)>, Self::Error>> + Send;

    fn load_second_rounds(
        &self,
    ) -> impl Future<Output = Result<Vec<(Musig2SessionId, SecondRound)>, Self::Error>> + Send;
}
