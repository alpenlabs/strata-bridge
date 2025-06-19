//! Stake Chain preimages client

use std::sync::Arc;

use bitcoin::{hashes::Hash, Txid};
use quinn::Connection;
use secret_service_proto::v2::{
    traits::{Client, ClientError, Origin, StakeChainPreimages},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v2_req, Config};

/// Stake Chain preimages client.
#[derive(Debug, Clone)]
pub struct StakeChainPreimgClient {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl StakeChainPreimgClient {
    /// Creates a new Stake Chain preimages client with an existing QUIC connection and
    /// configuration.
    pub const fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl StakeChainPreimages<Client> for StakeChainPreimgClient {
    async fn get_preimg(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> <Client as Origin>::Container<[u8; 32]> {
        let msg = ClientMessage::StakeChainGetPreimage {
            prestake_txid: prestake_txid.to_byte_array(),
            prestake_vout,
            stake_index,
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::StakeChainGetPreimage { preimg } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(preimg)
    }
}
