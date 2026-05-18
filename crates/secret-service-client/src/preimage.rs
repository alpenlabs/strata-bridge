//! Preimages client

use std::sync::Arc;

use bitcoin::{hashes::Hash, Txid};
use quinn::Connection;
use secret_service_proto::v2::{
    traits::{Client, ClientError, Origin, Preimages},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v2_req, Config};

/// Preimages client.
#[derive(Debug, Clone)]
pub struct PreimgClient {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl PreimgClient {
    /// Creates a new preimages client with an existing QUIC connection and
    /// configuration.
    pub const fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl Preimages<Client> for PreimgClient {
    async fn get_preimg(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> <Client as Origin>::Container<[u8; 32]> {
        let msg = ClientMessage::GetPreimage {
            prestake_txid: prestake_txid.to_byte_array(),
            prestake_vout,
            stake_index,
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::GetPreimage { preimg } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(preimg)
    }
}
