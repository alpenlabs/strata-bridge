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
    async fn get_128_secret_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> <Client as Origin>::Container<[u8; 20 * 36]> {
        let msg = ClientMessage::WotsGet128SecretKey {
            index,
            prestake_vout: vout,
            prestake_txid: txid.as_raw_hash().to_byte_array(),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::WotsGet128SecretKey { key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(key)
    }

    async fn get_256_secret_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> <Client as Origin>::Container<[u8; 20 * 68]> {
        let msg = ClientMessage::WotsGet256SecretKey {
            index,
            prestake_vout: vout,
            prestake_txid: txid.as_raw_hash().to_byte_array(),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::WotsGet256SecretKey { key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(key)
    }

    async fn get_128_public_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> <Client as Origin>::Container<[u8; 20 * 36]> {
        let msg = ClientMessage::WotsGet128PublicKey {
            index,
            prestake_vout: vout,
            prestake_txid: txid.as_raw_hash().to_byte_array(),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::WotsGet128PublicKey { key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(key)
    }

    async fn get_256_public_key(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
    ) -> <Client as Origin>::Container<[u8; 20 * 68]> {
        let msg = ClientMessage::WotsGet256PublicKey {
            index,
            prestake_vout: vout,
            prestake_txid: txid.as_raw_hash().to_byte_array(),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::WotsGet256PublicKey { key } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(key)
    }

    async fn get_128_signature(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
        msg: &[u8; 16],
    ) -> <Client as Origin>::Container<[u8; 20 * 36]> {
        let wire_msg = ClientMessage::WotsGet128Signature {
            index,
            prestake_vout: vout,
            prestake_txid: txid.as_raw_hash().to_byte_array(),
            msg: *msg,
        };
        let res = make_v1_req(&self.conn, wire_msg, self.config.timeout).await?;
        let ServerMessage::WotsGet128Signature { sig } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(sig)
    }

    async fn get_256_signature(
        &self,
        txid: Txid,
        vout: u32,
        index: u32,
        msg: &[u8; 32],
    ) -> <Client as Origin>::Container<[u8; 20 * 68]> {
        let wire_msg = ClientMessage::WotsGet256Signature {
            index,
            prestake_vout: vout,
            prestake_txid: txid.as_raw_hash().to_byte_array(),
            msg: *msg,
        };
        let res = make_v1_req(&self.conn, wire_msg, self.config.timeout).await?;
        let ServerMessage::WotsGet256Signature { sig } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(sig)
    }
}
