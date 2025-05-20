#![expect(incomplete_features)]
#![feature(generic_const_exprs)]
//! This module contains the implementation of the secret service server.
//!
//! This handles networking and communication with clients, but does not implement the traits
//! for the secret service protocol.

pub mod musig2_session_mgr;

use std::{collections::BTreeMap, io, marker::Sync, net::SocketAddr, sync::Arc};

use bitcoin::{hashes::Hash, TapNodeHash, Txid, XOnlyPublicKey};
use musig2::{errors::RoundFinalizeError, PartialSignature, PubNonce};
use musig2_session_mgr::{Musig2SessionManager, SessionAlreadyPresent};
pub use quinn::rustls;
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicServerConfig},
    ConnectionError, Endpoint, Incoming, ReadExactError, RecvStream, SendStream, ServerConfig,
    WriteError,
};
use rkyv::{rancor::Error, util::AlignedVec};
use secret_service_proto::{
    v1::{
        traits::{
            Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound, P2PSigner,
            SchnorrSigner, SecretService, Server, StakeChainPreimages, WotsSigner,
        },
        wire::{ClientMessage, Musig2NewSessionError, ServerMessage, SignerTarget},
    },
    wire::{LengthUint, VersionedClientMessage, VersionedServerMessage, WireMessage},
};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;
use terrors::{OneOf, E3};
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::{error, span, warn, Instrument, Level};

/// Configuration for the secret service server.
#[derive(Debug)]
pub struct Config {
    /// The address to bind the server to.
    pub addr: SocketAddr,

    /// The maximum number of concurrent connections allowed.
    pub connection_limit: Option<usize>,

    /// The TLS configuration for the server.
    pub tls_config: rustls::ServerConfig,
}

/// Runs the secret service server given the service and a server configuration.
pub async fn run_server<FirstRound, SecondRound, Service>(
    c: Config,
    service: Arc<Service>,
) -> Result<(), OneOf<(NoInitialCipherSuite, io::Error)>>
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound> + 'static,
    SecondRound: Musig2SignerSecondRound<Server> + 'static,
    Service: SecretService<Server, FirstRound, SecondRound> + Sync + 'static,
{
    let quic_server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(c.tls_config).map_err(OneOf::new)?,
    ));
    let endpoint = Endpoint::server(quic_server_config, c.addr).map_err(OneOf::new)?;
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
    Ok(())
}

/// Handles a single incoming connection.
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
                break;
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

/// Manages the stream of requests.
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
            let (len_bytes, msg_bytes) = match VersionedServerMessage::V1(msg).serialize() {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to serialize response: {e:?}");
                    return;
                }
            };
            let write = || async move {
                tx.write_all(&len_bytes).await?;
                tx.write_all(&msg_bytes).await?;
                Ok::<_, WriteError>(())
            };
            if let Err(e) = write().await {
                warn!("failed to send response: {e:?}");
            }
        }
        Err(e) => warn!("handler failed to read: {e:?}"),
    }
}

/// Manages the stream of requests.
async fn request_handler<Service, FirstRound, SecondRound>(
    mut rx: RecvStream,
    service: Arc<Service>,
    musig2_sm: Arc<Mutex<Musig2SessionManager<FirstRound, SecondRound>>>,
) -> Result<ServerMessage, ReadExactError>
where
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    SecondRound: Musig2SignerSecondRound<Server>,
    Service: SecretService<Server, FirstRound, SecondRound>,
{
    let len_to_read = {
        let mut buf = [0; size_of::<LengthUint>()];
        rx.read_exact(&mut buf).await?;
        LengthUint::from_le_bytes(buf)
    };

    let mut buf = AlignedVec::<16>::with_capacity(len_to_read as usize);
    buf.resize(len_to_read as usize, 0);
    rx.read_exact(&mut buf).await?;

    let msg = rkyv::from_bytes::<VersionedClientMessage, Error>(&buf).unwrap();
    Ok(match msg {
        // this would be a separate function but tokio would start whining because !Sync
        VersionedClientMessage::V1(msg) => match msg {
            ClientMessage::P2PSecretKey => {
                let key = service.p2p_signer().secret_key().await;
                ServerMessage::P2PSecretKey {
                    key: key.secret_bytes(),
                }
            }

            ClientMessage::Musig2NewSession {
                pubkeys,
                witness,
                input_txid,
                input_vout,
                session_id,
            } => 'block: {
                let signer = service.musig2_signer();

                let witness = match TaprootWitness::try_from(witness) {
                    Ok(w) => w,
                    Err(e) => {
                        break 'block ServerMessage::InvalidClientMessage(format!(
                            "invalid taproot witness: {e}"
                        ))
                    }
                };
                let pubkeys = match pubkeys
                    .iter()
                    .map(|data| XOnlyPublicKey::from_slice(data))
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(pks) => pks,
                    Err(e) => {
                        break 'block ServerMessage::InvalidClientMessage(format!(
                            "invalid public key: {e}"
                        ))
                    }
                };

                let first_round = match signer
                    .new_session(
                        session_id,
                        pubkeys,
                        witness,
                        Txid::from_byte_array(input_txid),
                        input_vout,
                    )
                    .await
                {
                    Ok(r1) => r1,
                    Err(e) => {
                        break 'block ServerMessage::Musig2NewSession(Err(
                            Musig2NewSessionError::SignerIdxOutOfBounds(e),
                        ))
                    }
                };
                let mut sm = musig2_sm.lock().await;
                if let Err(SessionAlreadyPresent) = sm.new_session(session_id, first_round) {
                    break 'block ServerMessage::Musig2NewSession(Err(
                        Musig2NewSessionError::SessionAlreadyPresent,
                    ));
                }
                ServerMessage::Musig2NewSession(Ok(()))
            }

            ClientMessage::WalletSignerSign {
                target,
                digest,
                tweak,
            } => {
                let tweak =
                    tweak.map(|h| TapNodeHash::from_slice(&h).expect("guaranteed correct length"));
                let sig = match target {
                    SignerTarget::General => {
                        service.general_wallet_signer().sign(&digest, tweak).await
                    }
                    SignerTarget::Stakechain => {
                        service
                            .stakechain_wallet_signer()
                            .sign(&digest, tweak)
                            .await
                    }
                    SignerTarget::Musig2 => service.musig2_signer().sign(&digest, tweak).await,
                };
                ServerMessage::WalletSignerSign {
                    sig: sig.serialize(),
                }
            }

            ClientMessage::WalletSignerSignNoTweak { target, digest } => {
                let sig = match target {
                    SignerTarget::General => {
                        service.general_wallet_signer().sign_no_tweak(&digest).await
                    }
                    SignerTarget::Stakechain => {
                        service
                            .stakechain_wallet_signer()
                            .sign_no_tweak(&digest)
                            .await
                    }
                    SignerTarget::Musig2 => service.musig2_signer().sign_no_tweak(&digest).await,
                };
                ServerMessage::WalletSignerSign {
                    sig: sig.serialize(),
                }
            }

            ClientMessage::WalletSignerPubkey { target } => ServerMessage::WalletSignerPubkey {
                pubkey: match target {
                    SignerTarget::General => {
                        service.general_wallet_signer().pubkey().await.serialize()
                    }
                    SignerTarget::Stakechain => service
                        .stakechain_wallet_signer()
                        .pubkey()
                        .await
                        .serialize(),
                    SignerTarget::Musig2 => service.musig2_signer().pubkey().await.serialize(),
                },
            },

            ClientMessage::Musig2FirstRoundOurNonce { session_id } => {
                match musig2_sm.lock().await.first_round(&session_id) {
                    Some(first_round) => {
                        let our_nonce = first_round.lock().await.our_nonce().await.serialize();
                        ServerMessage::Musig2FirstRoundOurNonce { our_nonce }
                    }
                    None => ServerMessage::InvalidClientMessage("no round present".to_owned()),
                }
            }

            ClientMessage::Musig2FirstRoundHoldouts { session_id } => {
                match musig2_sm.lock().await.first_round(&session_id) {
                    Some(first_round) => ServerMessage::Musig2FirstRoundHoldouts {
                        pubkeys: first_round
                            .lock()
                            .await
                            .holdouts()
                            .await
                            .iter()
                            .map(XOnlyPublicKey::serialize)
                            .collect(),
                    },
                    None => ServerMessage::InvalidClientMessage("no round present".to_owned()),
                }
            }

            ClientMessage::Musig2FirstRoundIsComplete { session_id } => {
                match musig2_sm.lock().await.first_round(&session_id) {
                    Some(r1) => ServerMessage::Musig2FirstRoundIsComplete {
                        complete: r1.lock().await.is_complete().await,
                    },
                    None => ServerMessage::InvalidClientMessage("no round present".to_owned()),
                }
            }

            ClientMessage::Musig2FirstRoundReceivePubNonce { session_id, nonces } => {
                let session_id = &session_id;
                let r1 = match musig2_sm.lock().await.first_round(session_id) {
                    Some(r1) => r1,
                    None => {
                        return Ok(ServerMessage::InvalidClientMessage(
                            "no round present".to_owned(),
                        ))
                    }
                };
                let nonces = match nonces
                    .iter()
                    .map(|(pk, nonce)| {
                        let pk = match XOnlyPublicKey::from_slice(pk) {
                            Ok(pk) => pk,
                            Err(e) => {
                                return Err(ServerMessage::InvalidClientMessage(format!(
                                    "invalid pubkey: {e}"
                                )))
                            }
                        };
                        let pubnonce = match PubNonce::from_bytes(nonce) {
                            Ok(nonce) => nonce,
                            Err(e) => {
                                return Err(ServerMessage::InvalidClientMessage(format!(
                                    "invalid pubnonce: {e:}"
                                )))
                            }
                        };
                        Ok((pk, pubnonce))
                    })
                    .collect::<Result<BTreeMap<XOnlyPublicKey, PubNonce>, ServerMessage>>()
                {
                    Ok(nonces) => nonces,
                    Err(e) => return Ok(e),
                };

                let result = r1.lock().await.receive_pub_nonces(nonces.into_iter()).await;
                ServerMessage::Musig2FirstRoundReceivePubNonce(match result {
                    Ok(()) => BTreeMap::new(),
                    Err(e) => e
                        .into_iter()
                        .map(|(pk, err)| (pk.serialize(), err))
                        .collect(),
                })
            }

            ClientMessage::Musig2FirstRoundFinalize { session_id, digest } => {
                let mut sm = musig2_sm.lock().await;
                let r = sm
                    .transition_first_to_second_round(session_id, digest)
                    .await;

                if let Err(e) = r {
                    use terrors::E2::*;
                    match e.narrow::<RoundFinalizeError, _>() {
                        Ok(e) => ServerMessage::Musig2FirstRoundFinalize(Some(e)),
                        Err(e) => match e.as_enum() {
                            A(not_in_correct_round) => ServerMessage::InvalidClientMessage(
                                format!("{not_in_correct_round:?}"),
                            ),
                            B(_other_refs_active) => ServerMessage::TryAgain,
                        },
                    }
                } else {
                    ServerMessage::Musig2FirstRoundFinalize(None)
                }
            }

            ClientMessage::Musig2SecondRoundAggNonce { session_id } => {
                match musig2_sm.lock().await.second_round(&session_id) {
                    Some(r2) => ServerMessage::Musig2SecondRoundAggNonce {
                        nonce: r2.lock().await.agg_nonce().await.serialize(),
                    },
                    None => ServerMessage::InvalidClientMessage("no round present".to_owned()),
                }
            }
            ClientMessage::Musig2SecondRoundHoldouts { session_id } => {
                match musig2_sm.lock().await.second_round(&session_id) {
                    Some(r2) => ServerMessage::Musig2SecondRoundHoldouts {
                        pubkeys: r2
                            .lock()
                            .await
                            .holdouts()
                            .await
                            .iter()
                            .map(XOnlyPublicKey::serialize)
                            .collect(),
                    },
                    None => ServerMessage::InvalidClientMessage("no round present".to_owned()),
                }
            }

            ClientMessage::Musig2SecondRoundOurSignature { session_id } => {
                match musig2_sm.lock().await.second_round(&session_id) {
                    Some(r2) => ServerMessage::Musig2SecondRoundOurSignature {
                        sig: r2.lock().await.our_signature().await.serialize(),
                    },
                    None => ServerMessage::InvalidClientMessage("no round present".to_owned()),
                }
            }

            ClientMessage::Musig2SecondRoundIsComplete { session_id } => {
                match musig2_sm.lock().await.second_round(&session_id) {
                    Some(r2) => ServerMessage::Musig2SecondRoundIsComplete {
                        complete: r2.lock().await.is_complete().await,
                    },
                    None => ServerMessage::InvalidClientMessage("no round present".to_owned()),
                }
            }

            ClientMessage::Musig2SecondRoundReceiveSignature { session_id, sigs } => {
                let session_id = &session_id;
                let r2 = match musig2_sm.lock().await.second_round(session_id) {
                    Some(r2) => r2,
                    None => {
                        return Ok(ServerMessage::InvalidClientMessage(
                            "no round present".to_owned(),
                        ))
                    }
                };

                let sigs = match sigs
                    .iter()
                    .map(|(pk, sig)| {
                        let pk = match XOnlyPublicKey::from_slice(pk) {
                            Ok(pk) => pk,
                            Err(e) => {
                                return Err(ServerMessage::InvalidClientMessage(format!(
                                    "invalid pubkey: {e}"
                                )))
                            }
                        };
                        let partial_sig = match PartialSignature::from_slice(sig) {
                            Ok(partial_sig) => partial_sig,
                            Err(e) => {
                                return Err(ServerMessage::InvalidClientMessage(format!(
                                    "invalid partial sig: {e}"
                                )))
                            }
                        };
                        Ok((pk, partial_sig))
                    })
                    .collect::<Result<BTreeMap<XOnlyPublicKey, PartialSignature>, ServerMessage>>()
                {
                    Ok(nonces) => nonces,
                    Err(e) => return Ok(e),
                };

                let result = r2.lock().await.receive_signatures(sigs.into_iter()).await;
                ServerMessage::Musig2SecondRoundReceiveSignature(match result {
                    Ok(()) => BTreeMap::new(),
                    Err(e) => e
                        .into_iter()
                        .map(|(pk, err)| (pk.serialize(), err))
                        .collect(),
                })
            }

            ClientMessage::Musig2SecondRoundFinalize { session_id } => {
                let r = musig2_sm
                    .lock()
                    .await
                    .finalize_second_round(session_id)
                    .await;
                match r {
                    Ok(sig) => ServerMessage::Musig2SecondRoundFinalize(Ok(sig.serialize()).into()),
                    Err(e) => match e.as_enum() {
                        E3::A(e) => ServerMessage::InvalidClientMessage(format!("{e:?}")),
                        E3::B(_other_refs_active) => ServerMessage::TryAgain,
                        E3::C(round_finalize_err) => ServerMessage::Musig2SecondRoundFinalize(
                            Err(round_finalize_err.to_owned()).into(),
                        ),
                    },
                }
            }

            ClientMessage::WotsGet128SecretKey { specifier } => {
                let txid = Txid::from_slice(&specifier.txid).expect("correct length");
                let key = service
                    .wots_signer()
                    .get_128_secret_key(txid, specifier.vout, specifier.index)
                    .await;
                ServerMessage::WotsGet128SecretKey { key }
            }

            ClientMessage::WotsGet256SecretKey { specifier } => {
                let txid = Txid::from_slice(&specifier.txid).expect("correct length");
                let key = service
                    .wots_signer()
                    .get_256_secret_key(txid, specifier.vout, specifier.index)
                    .await;
                ServerMessage::WotsGet256SecretKey { key }
            }

            ClientMessage::WotsGet128PublicKey { specifier } => {
                let txid = Txid::from_slice(&specifier.txid).expect("correct length");
                let key = service
                    .wots_signer()
                    .get_128_public_key(txid, specifier.vout, specifier.index)
                    .await;
                ServerMessage::WotsGet128PublicKey { key }
            }

            ClientMessage::WotsGet256PublicKey { specifier } => {
                let txid = Txid::from_slice(&specifier.txid).expect("correct length");
                let key = service
                    .wots_signer()
                    .get_256_public_key(txid, specifier.vout, specifier.index)
                    .await;
                ServerMessage::WotsGet256PublicKey { key }
            }

            ClientMessage::WotsGet128Signature { specifier, msg } => {
                let txid = Txid::from_slice(&specifier.txid).expect("correct length");
                let sig = service
                    .wots_signer()
                    .get_128_signature(txid, specifier.vout, specifier.index, &msg)
                    .await;
                ServerMessage::WotsGet128Signature { sig }
            }

            ClientMessage::WotsGet256Signature { specifier, msg } => {
                let txid = Txid::from_slice(&specifier.txid).expect("correct length");
                let sig = service
                    .wots_signer()
                    .get_256_signature(txid, specifier.vout, specifier.index, &msg)
                    .await;
                ServerMessage::WotsGet256Signature { sig }
            }

            ClientMessage::StakeChainGetPreimage {
                prestake_txid,
                prestake_vout,
                stake_index,
            } => {
                let preimg = service
                    .stake_chain_preimages()
                    .get_preimg(
                        Txid::from_slice(&prestake_txid).expect("correct length"),
                        prestake_vout,
                        stake_index,
                    )
                    .await;
                ServerMessage::StakeChainGetPreimage { preimg }
            }
        },
    })
}
