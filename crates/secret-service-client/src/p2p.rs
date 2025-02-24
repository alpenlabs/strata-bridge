//! P2P signer client

use std::{future::Future, sync::Arc};

use bitcoin::XOnlyPublicKey;
use musig2::secp256k1::schnorr::Signature;
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, Origin, P2PSigner},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

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
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl P2PSigner<Client> for P2PClient {
    fn sign(
        &self,
        digest: &[u8; 32],
    ) -> impl Future<Output = <Client as Origin>::Container<Signature>> + Send {
        async move {
            let msg = ClientMessage::P2PSign { digest: *digest };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::P2PSign { sig } = res else {
                return Err(ClientError::WrongMessage(res.into()));
            };
            Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
        }
    }

    fn pubkey(&self) -> impl Future<Output = <Client as Origin>::Container<XOnlyPublicKey>> + Send {
        async move {
            let msg = ClientMessage::P2PPubkey;
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::P2PPubkey { pubkey } = res else {
                return Err(ClientError::WrongMessage(res.into()));
            };
            XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
        }
    }
}
