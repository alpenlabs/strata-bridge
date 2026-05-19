#![allow(clippy::manual_async_fn)]
//! The client crate for the secret service. Provides implementations of the traits that use a QUIC
//! connection and wire protocol defined in the [`secret_service_proto`] crate to connect with a
//! remote secret service.

pub mod musig2;
pub mod p2p;
pub mod preimage;
pub mod wallet;

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use musig2::Musig2Client;
use p2p::P2PClient;
use preimage::PreimgClient;
pub use quinn::rustls;
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
    ClientConfig, ConnectError, Connection, ConnectionError, Endpoint, ReadExactError,
    TransportConfig, WriteError,
};
use rkyv::{deserialize, rancor, util::AlignedVec};
use secret_service_proto::{
    v2::{
        traits::{Client, ClientError, SecretService},
        wire::{ClientMessage, ServerMessage},
    },
    wire::{
        ArchivedVersionedServerMessage, LengthUint, VersionedClientMessage, VersionedServerMessage,
        WireMessage,
    },
};
use terrors::OneOf;
use tokio::{sync::RwLock, time::timeout};
use tracing::{info, warn};
use wallet::{GeneralWalletClient, ReservedWalletClient};

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// Maximum number of times a request is retried inside [`v2_req`] when the server responds with
/// [`ServerMessage::TryAgain`].
const MAX_RETRIES: usize = 10;

/// Configuration for the Secret Service client.
#[derive(Clone, Debug)]
pub struct Config {
    /// Server to connect to.
    pub server_addr: SocketAddr,

    /// Hostname present on the server's certificate.
    pub server_hostname: String,

    /// Optional local socket to connect via.
    pub local_addr: Option<SocketAddr>,

    /// Config for TLS.
    ///
    /// # Warning
    ///
    /// Users should always be verifying the server's identity via this to prevent MITM attacks.
    pub tls_config: rustls::ClientConfig,

    /// Timeout for requests.
    pub timeout: Duration,
}

/// Shared connection handle held by all per-signer clients.
///
/// Owns the live QUIC [`Connection`] plus the [`Endpoint`] and dial parameters needed to
/// re-establish the connection if it dies mid-session. Reconnect is lazy: a failed request whose
/// error signals the connection is dead triggers a single reconnect attempt and one retry inside
/// [`ConnHandle::make_v2_req`]; if the retry also fails the error is propagated.
///
/// Clones are cheap — the inner state lives behind an [`Arc`].
#[derive(Debug, Clone)]
pub(crate) struct ConnHandle {
    inner: Arc<ConnHandleInner>,
}

#[derive(Debug)]
struct ConnHandleInner {
    /// Current QUIC connection. Swapped out on reconnect.
    conn: RwLock<Connection>,
    /// Reusable QUIC endpoint — survives across reconnects.
    endpoint: Endpoint,
    /// Cloned per `connect_with` call (quinn consumes it by value).
    client_config: ClientConfig,
    /// Server address.
    server_addr: SocketAddr,
    /// Server TLS hostname.
    server_hostname: String,
    /// Per-request timeout.
    timeout: Duration,
}

impl ConnHandle {
    /// Snapshot the current connection. Cheap — [`Connection`] is Arc internally.
    async fn current(&self) -> Connection {
        self.inner.conn.read().await.clone()
    }

    /// Reconnect to the server, but only if the caller's snapshot is still the live connection.
    /// Returns the freshly-installed connection (which may be the one another caller already
    /// reconnected to if we lost the race).
    async fn reconnect_if_stale(&self, stale: &Connection) -> Result<Connection, ClientError> {
        let mut guard = self.inner.conn.write().await;
        // Another caller may have reconnected while we were waiting for the write lock; bail with
        // their fresh connection rather than churning.
        if guard.stable_id() != stale.stable_id() {
            return Ok(guard.clone());
        }
        info!(
            server = %self.inner.server_addr,
            "secret-service connection lost; reconnecting",
        );
        let connecting = self
            .inner
            .endpoint
            .connect_with(
                self.inner.client_config.clone(),
                self.inner.server_addr,
                &self.inner.server_hostname,
            )
            // `connect_with` fails for malformed config; we used the same config successfully at
            // construction time, so a failure here means the system is in a degenerate state.
            // Surface it as a generic reset.
            .map_err(|e| {
                warn!(?e, "secret-service reconnect dial failed");
                ClientError::ConnectionError(ConnectionError::Reset)
            })?;
        // Bound the handshake by the same per-request timeout so a hung dial does not block
        // every other signer call waiting on this write lock.
        let new_conn = timeout(self.inner.timeout, connecting)
            .await
            .map_err(|_| {
                warn!("secret-service reconnect handshake timed out");
                ClientError::Timeout
            })?
            .map_err(|e| {
                warn!(?e, "secret-service reconnect handshake failed");
                ClientError::ConnectionError(e)
            })?;
        info!(
            server = %self.inner.server_addr,
            "secret-service reconnect succeeded",
        );
        *guard = new_conn.clone();
        Ok(new_conn)
    }

    /// Makes a v2 secret service request via QUIC, transparently reconnecting on dead-connection
    /// errors and per-request timeouts. Application-level errors (`TryAgain` exhaustion,
    /// deserialization failures, etc.) are propagated to the caller without reconnecting.
    pub(crate) async fn make_v2_req(
        &self,
        msg: ClientMessage,
    ) -> Result<ServerMessage, ClientError> {
        let conn = self.current().await;
        // Try once on the current connection. On dead-connection errors only, reconnect and retry
        // once more with the fresh connection. Note: we clone `msg` only on the retry path so the
        // happy path pays just one clone (inside `v2_req` for serialization).
        match v2_req(&conn, msg.clone(), self.inner.timeout, MAX_RETRIES).await {
            Ok(m) => Ok(m),
            Err(e) if should_reconnect(&e) => {
                let new_conn = self.reconnect_if_stale(&conn).await?;
                v2_req(&new_conn, msg, self.inner.timeout, MAX_RETRIES).await
            }
            Err(e) => Err(e),
        }
    }
}

/// Returns true if `err` warrants a reconnect attempt.
///
/// Reconnect on:
/// - explicit dead-connection signals from quinn (closed, reset, locally-closed, etc.)
/// - per-request `Timeout` — a slow server costs at most one wasted reconnect, but a server that
///   has died without yet tripping the QUIC idle-timeout / keep-alive would otherwise keep timing
///   out indefinitely.
///
/// Application-level errors (retry exhaustion, malformed payloads, serialization failures)
/// are propagated.
const fn should_reconnect(err: &ClientError) -> bool {
    match err {
        ClientError::ConnectionError(ce) => matches!(
            ce,
            ConnectionError::ApplicationClosed(_)
                | ConnectionError::ConnectionClosed(_)
                | ConnectionError::Reset
                | ConnectionError::TimedOut
                | ConnectionError::LocallyClosed
        ),
        ClientError::WriteError(we) => matches!(we, WriteError::ConnectionLost(_)),
        ClientError::ReadError(re) => matches!(
            re,
            ReadExactError::ReadError(quinn::ReadError::ConnectionLost(_))
        ),
        ClientError::Timeout => true,
        // Per-request errors that do not indicate a dead connection. Listed exhaustively rather
        // than caught by a wildcard so any new `ClientError` variant forces a deliberate
        // classification decision here at compile time.
        ClientError::SerializationError(_)
        | ClientError::DeserializationError(_)
        | ClientError::BadData
        | ClientError::NoMoreRetries
        | ClientError::WrongMessage(_)
        | ClientError::WrongVersion => false,
    }
}

/// A client that connects to a remote secret service via QUIC.
#[derive(Clone, Debug)]
pub struct SecretServiceClient {
    /// Shared connection handle. Reconnects on transport failure are transparent to callers.
    conn: ConnHandle,
}

impl SecretServiceClient {
    /// Creates a new client and attempt to connect to the server.
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

        let mut transport_config = TransportConfig::default();

        transport_config.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));

        let mut client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(config.tls_config.clone()).map_err(OneOf::new)?,
        ));
        client_config.transport_config(transport_config.into());

        let connecting = endpoint
            .connect_with(
                client_config.clone(),
                config.server_addr,
                &config.server_hostname,
            )
            .map_err(OneOf::new)?;
        let conn = connecting.await.map_err(OneOf::new)?;

        let conn = ConnHandle {
            inner: Arc::new(ConnHandleInner {
                conn: RwLock::new(conn),
                endpoint,
                client_config,
                server_addr: config.server_addr,
                server_hostname: config.server_hostname.clone(),
                timeout: config.timeout,
            }),
        };

        Ok(SecretServiceClient { conn })
    }
}

impl SecretService<Client> for SecretServiceClient {
    type GeneralWalletSigner = GeneralWalletClient;
    type ReservedWalletSigner = ReservedWalletClient;

    type P2PSigner = P2PClient;

    type Musig2Signer = Musig2Client;

    type Preimages = PreimgClient;

    fn general_wallet_signer(&self) -> Self::GeneralWalletSigner {
        GeneralWalletClient::new(self.conn.clone())
    }

    fn reserved_wallet_signer(&self) -> Self::ReservedWalletSigner {
        ReservedWalletClient::new(self.conn.clone())
    }

    fn p2p_signer(&self) -> Self::P2PSigner {
        P2PClient::new(self.conn.clone())
    }

    fn musig2_signer(&self) -> Self::Musig2Signer {
        Musig2Client::new(self.conn.clone())
    }

    fn preimages(&self) -> Self::Preimages {
        PreimgClient::new(self.conn.clone())
    }
}

/// Issues a single v2 request over the given connection. Caller is responsible for retry on
/// transport failure — see [`ConnHandle::make_v2_req`].
async fn v2_req(
    conn: &Connection,
    msg: ClientMessage,
    timeout_dur: Duration,
    retries: usize,
) -> Result<ServerMessage, ClientError> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(ClientError::ConnectionError)?;
    let (len_bytes, msg_bytes) = VersionedClientMessage::V2(msg.clone())
        .serialize()
        .map_err(ClientError::SerializationError)?;
    timeout(timeout_dur, tx.write_all(&len_bytes))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::WriteError)?;
    timeout(timeout_dur, tx.write_all(&msg_bytes))
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

    let mut buf: AlignedVec<16> = AlignedVec::with_capacity(len_to_read as usize);
    buf.resize(len_to_read as usize, 0);
    timeout(timeout_dur, rx.read_exact(&mut buf))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::ReadError)?;

    let archived = rkyv::access::<ArchivedVersionedServerMessage, rancor::Error>(&buf)
        .map_err(ClientError::DeserializationError)?;

    let VersionedServerMessage::V2(srv_msg) =
        deserialize(archived).map_err(ClientError::DeserializationError)?;

    if let ServerMessage::TryAgain = srv_msg {
        if retries == 0 {
            return Err(ClientError::NoMoreRetries);
        } else {
            return Box::pin(v2_req(conn, msg, timeout_dur, retries - 1)).await;
        }
    }

    Ok(srv_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_reconnect_classifies_errors() {
        // Connection-level errors that mean "the connection is dead" -> reconnect.
        assert!(should_reconnect(&ClientError::ConnectionError(
            ConnectionError::Reset,
        )));
        assert!(should_reconnect(&ClientError::ConnectionError(
            ConnectionError::TimedOut,
        )));
        assert!(should_reconnect(&ClientError::ConnectionError(
            ConnectionError::LocallyClosed,
        )));

        // Per-request `Timeout` also triggers reconnect — a server that has died without yet
        // tripping QUIC's idle-timeout would otherwise keep timing out forever.
        assert!(should_reconnect(&ClientError::Timeout));

        // Application-level errors -> propagate, do not reconnect.
        assert!(!should_reconnect(&ClientError::NoMoreRetries));
        assert!(!should_reconnect(&ClientError::BadData));
    }
}
