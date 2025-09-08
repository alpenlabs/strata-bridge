//! P2P signer client

use std::sync::Arc;

use quinn::Connection;
use secret_service_proto::v2::{
    traits::{Client, ClientError, Ed25519Signer, Origin},
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

impl Ed25519Signer<Client> for P2PClient {
    async fn sign(&self, digest: &[u8; 32]) -> <Client as Origin>::Container<ed25519::Signature> {
        let msg = ClientMessage::Ed25519SignerSign { digest: *digest };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        if let ServerMessage::Ed25519SignerSign { sig } = res {
            Ok(ed25519::Signature::from_bytes(&sig))
        } else {
            Err(ClientError::WrongMessage(res.into()))
        }
    }

    async fn pubkey(&self) -> <Client as Origin>::Container<[u8; 32]> {
        let msg = ClientMessage::Ed25519SignerPubkey;
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        if let ServerMessage::Ed25519SignerPubkey { pubkey } = res {
            Ok(pubkey)
        } else {
            Err(ClientError::WrongMessage(res.into()))
        }
    }
}
