//! WOTS signer client
use std::{future::Future, sync::Arc};

use bitcoin::{hashes::Hash, Txid};
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, Origin, WotsSigner},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

pub struct WotsClient {
    conn: Connection,
    config: Arc<Config>,
}

impl WotsClient {
    /// Creates a new wots client with an existing quic connection and config
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl WotsSigner<Client> for WotsClient {
    fn get_160_key(
        &self,
        index: u32,
        vout: u32,
        txid: Txid,
    ) -> impl Future<Output = <Client as Origin>::Container<[u8; 20 * 160]>> + Send {
        async move {
            let msg = ClientMessage::WotsGet160Key {
                index,
                vout,
                txid: txid.as_raw_hash().to_byte_array(),
            };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::WotsGet160Key { key } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(key)
        }
    }

    fn get_256_key(
        &self,
        index: u32,
        vout: u32,
        txid: Txid,
    ) -> impl Future<Output = <Client as Origin>::Container<[u8; 20 * 256]>> + Send {
        async move {
            let msg = ClientMessage::WotsGet256Key {
                index,
                vout,
                txid: txid.as_raw_hash().to_byte_array(),
            };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::WotsGet256Key { key } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(key)
        }
    }
}
