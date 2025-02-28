//! Winternitz One-time Signature (WOTS) signer client
use std::sync::Arc;

use bitcoin::{hashes::Hash, Txid};
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, Origin, WotsSigner},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

/// Winternitz One-time Signature (WOTS) signer client.
#[derive(Debug, Clone)]
pub struct WotsClient {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl WotsClient {
    /// Creates a new WOTS client with an existing QUIC connection and configuration.
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl WotsSigner<Client> for WotsClient {
    async fn get_160_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> <Client as Origin>::Container<[u8; 20 * 160]> {
        let msg = ClientMessage::WotsGet160Key {
            index,
            vout,
            txid: txid.as_raw_hash().to_byte_array(),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::WotsGet160Key { key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(key)
    }

    async fn get_256_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> <Client as Origin>::Container<[u8; 20 * 256]> {
        let msg = ClientMessage::WotsGet256Key {
            index,
            vout,
            txid: txid.as_raw_hash().to_byte_array(),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::WotsGet256Key { key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(key)
    }
}
