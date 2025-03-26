#![allow(clippy::manual_async_fn)]
//! The client crate for the secret service. Provides implementations of the traits that use a QUIC
//! connection and wire protocol defined in the [`secret_service_proto`] crate to connect with a
//! remote secret service.

pub mod musig2;
pub mod p2p;
pub mod stakechain;
pub mod wallet;

pub mod wots;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use musig2::{Musig2Client, Musig2FirstRound, Musig2SecondRound};
use p2p::P2PClient;
pub use quinn::rustls;
use quinn::{
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
    ClientConfig, ConnectError, Connection, ConnectionError, Endpoint, TransportConfig,
};
use rkyv::{deserialize, rancor, util::AlignedVec};
use secret_service_proto::{
    v1::{
        traits::{Client, ClientError, SecretService},
        wire::{ClientMessage, ServerMessage},
    },
    wire::{
        ArchivedVersionedServerMessage, LengthUint, VersionedClientMessage, VersionedServerMessage,
        WireMessage,
    },
};
use stakechain::StakeChainPreimgClient;
use terrors::OneOf;
use tokio::time::timeout;
use wallet::{GeneralWalletClient, StakechainWalletClient};
use wots::WotsClient;

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(25);

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

/// A client that connects to a remote secret service via QUIC.
#[derive(Clone, Debug)]
pub struct SecretServiceClient {
    /// Client configuration.
    config: Arc<Config>,

    /// QUIC connection to the server.
    conn: Connection,
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
            .connect_with(client_config, config.server_addr, &config.server_hostname)
            .map_err(OneOf::new)?;
        let conn = connecting.await.map_err(OneOf::new)?;

        Ok(SecretServiceClient {
            config: Arc::new(config),
            conn,
        })
    }
}

impl SecretService<Client, Musig2FirstRound, Musig2SecondRound> for SecretServiceClient {
    type GeneralWalletSigner = GeneralWalletClient;
    type StakechainWalletSigner = StakechainWalletClient;

    type P2PSigner = P2PClient;

    type Musig2Signer = Musig2Client;

    type WotsSigner = WotsClient;

    type StakeChainPreimages = StakeChainPreimgClient;

    fn general_wallet_signer(&self) -> Self::GeneralWalletSigner {
        GeneralWalletClient::new(self.conn.clone(), self.config.clone())
    }

    fn stakechain_wallet_signer(&self) -> Self::StakechainWalletSigner {
        StakechainWalletClient::new(self.conn.clone(), self.config.clone())
    }

    fn p2p_signer(&self) -> Self::P2PSigner {
        P2PClient::new(self.conn.clone(), self.config.clone())
    }

    fn musig2_signer(&self) -> Self::Musig2Signer {
        Musig2Client::new(self.conn.clone(), self.config.clone())
    }

    fn wots_signer(&self) -> Self::WotsSigner {
        WotsClient::new(self.conn.clone(), self.config.clone())
    }

    fn stake_chain_preimages(&self) -> Self::StakeChainPreimages {
        StakeChainPreimgClient::new(self.conn.clone(), self.config.clone())
    }
}

/// Makes a v1 secret service request via QUIC.
pub async fn make_v1_req(
    conn: &Connection,
    msg: ClientMessage,
    timeout_dur: Duration,
) -> Result<ServerMessage, ClientError> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(ClientError::ConnectionError)?;
    let (len_bytes, msg_bytes) = VersionedClientMessage::V1(msg)
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

    let VersionedServerMessage::V1(msg) =
        deserialize(archived).map_err(ClientError::DeserializationError)?;

    Ok(msg)
}
