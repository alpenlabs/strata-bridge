#![expect(incomplete_features)]
#![feature(generic_const_exprs)]
//! This module contains the implementation of the secret service server.
//!
//! This handles networking and communication with clients, but does not implement the traits
//! for the secret service protocol.

use std::{io, marker::Sync, net::SocketAddr, sync::Arc};

use bitcoin::{hashes::Hash, TapNodeHash, Txid};
use musig2::AggNonce;
pub use quinn::rustls;
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicServerConfig},
    ConnectionError, Endpoint, Incoming, ReadExactError, RecvStream, SendStream, ServerConfig,
    WriteError,
};
use rkyv::{rancor::Error, util::AlignedVec};
use secret_service_proto::{
    v2::{
        traits::{
            Ed25519Signer, Musig2Signer, SchnorrSigner, SecretService, Server, StakeChainPreimages,
            WotsSigner,
        },
        wire::{ClientMessage, ServerMessage, SignerTarget},
    },
    wire::{LengthUint, VersionedClientMessage, VersionedServerMessage, WireMessage},
};
use terrors::OneOf;
use tokio::task::JoinHandle;
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
pub async fn run_server<Service>(
    c: Config,
    service: Arc<Service>,
) -> Result<(), OneOf<(NoInitialCipherSuite, io::Error)>>
where
    Service: SecretService<Server> + Sync + 'static,
{
    let quic_server_config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(c.tls_config).map_err(OneOf::new)?,
    ));
    let endpoint = Endpoint::server(quic_server_config, c.addr).map_err(OneOf::new)?;
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
            tokio::spawn(conn_handler(incoming, service.clone()).instrument(span));
        }
    }
    Ok(())
}

/// Handles a single incoming connection.
async fn conn_handler<Service>(incoming: Incoming, service: Arc<Service>)
where
    Service: SecretService<Server> + Sync + 'static,
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
                tokio::spawn(request_handler(rx, service.clone()).instrument(handler_span)),
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
            let (len_bytes, msg_bytes) = match VersionedServerMessage::V2(msg).serialize() {
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
async fn request_handler<Service>(
    mut rx: RecvStream,
    service: Arc<Service>,
) -> Result<ServerMessage, ReadExactError>
where
    Service: SecretService<Server>,
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
        VersionedClientMessage::V2(msg) => match msg {
            ClientMessage::Musig2GetPubNonce { params } => {
                let params = match params.try_into() {
                    Ok(params) => params,
                    Err(e) => {
                        return Ok(ServerMessage::InvalidClientMessage(format!(
                            "invalid params: {e:?}"
                        )));
                    }
                };
                let res = service
                    .musig2_signer()
                    .get_pub_nonce(params)
                    .await
                    .map(|pn| pn.serialize());
                ServerMessage::Musig2GetPubNonce(res)
            }

            ClientMessage::Musig2GetOurPartialSig {
                params,
                aggnonce,
                message,
            } => {
                let params = match params.try_into() {
                    Ok(params) => params,
                    Err(e) => {
                        return Ok(ServerMessage::InvalidClientMessage(format!(
                            "invalid params: {e:?}"
                        )));
                    }
                };
                let aggnonce = match AggNonce::from_bytes(&aggnonce) {
                    Ok(aggnonce) => aggnonce,
                    Err(e) => {
                        return Ok(ServerMessage::InvalidClientMessage(format!(
                            "invalid aggnonce: {e:?}"
                        )));
                    }
                };
                let res = service
                    .musig2_signer()
                    .get_our_partial_sig(params, aggnonce, message)
                    .await
                    .map(|ps| ps.serialize());
                ServerMessage::Musig2GetOurPartialSig(res)
            }

            ClientMessage::SchnorrSignerSign {
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
                ServerMessage::SchnorrSignerSign {
                    sig: sig.serialize(),
                }
            }

            ClientMessage::SchnorrSignerSignNoTweak { target, digest } => {
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
                ServerMessage::SchnorrSignerSign {
                    sig: sig.serialize(),
                }
            }

            ClientMessage::SchnorrSignerPubkey { target } => ServerMessage::SchnorrSignerPubkey {
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

            ClientMessage::Ed25519SignerSign { digest } => {
                let sig = service.p2p_signer().sign(&digest).await;
                ServerMessage::Ed25519SignerSign {
                    sig: sig.to_bytes(),
                }
            }

            ClientMessage::Ed25519SignerPubkey => {
                let pubkey = service.p2p_signer().pubkey().await;
                ServerMessage::Ed25519SignerPubkey { pubkey }
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
