//! P2P signer client

use std::sync::Arc;

use libp2p_identity::ed25519::SecretKey;
use quinn::Connection;
use secret_service_proto::v2::{
    traits::{Client, ClientError, Origin, P2PSigner},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v2_req, Config};

/// P2P signer client.
#[derive(Debug, Clone)]
pub struct P2PClient {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl P2PClient {
    /// Creates a new P2P client with an existing QUIC connection and configuration.
    pub const fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl P2PSigner<Client> for P2PClient {
    async fn secret_key(&self) -> <Client as Origin>::Container<SecretKey> {
        let msg = ClientMessage::P2PSecretKey;
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::P2PSecretKey { mut key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(SecretKey::try_from_bytes(&mut key).expect("correct length"))
    }
}
