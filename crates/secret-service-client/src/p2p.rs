//! P2P signer client

use libp2p_identity::ed25519::SecretKey;
use secret_service_proto::v2::{
    traits::{Client, ClientError, Origin, P2PSigner},
    wire::{ClientMessage, ServerMessage},
};

use crate::ConnHandle;

/// P2P signer client.
#[derive(Debug, Clone)]
pub struct P2PClient {
    /// Shared QUIC connection handle (transparently reconnects on dead-connection errors).
    conn: ConnHandle,
}

impl P2PClient {
    /// Creates a new P2P client with the given shared connection handle.
    pub(crate) const fn new(conn: ConnHandle) -> Self {
        Self { conn }
    }
}

impl P2PSigner<Client> for P2PClient {
    async fn secret_key(&self) -> <Client as Origin>::Container<SecretKey> {
        let msg = ClientMessage::P2PSecretKey;
        let res = self.conn.make_v2_req(msg).await?;
        let ServerMessage::P2PSecretKey { mut key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(SecretKey::try_from_bytes(&mut key).expect("correct length"))
    }
}
