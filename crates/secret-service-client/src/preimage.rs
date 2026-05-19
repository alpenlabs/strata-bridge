//! Preimages client

use bitcoin::{hashes::Hash, Txid};
use secret_service_proto::v2::{
    traits::{Client, ClientError, Origin, Preimages},
    wire::{ClientMessage, ServerMessage},
};

use crate::ConnHandle;

/// Preimages client.
#[derive(Debug, Clone)]
pub struct PreimgClient {
    /// Shared QUIC connection handle (transparently reconnects on dead-connection errors).
    conn: ConnHandle,
}

impl PreimgClient {
    /// Creates a new preimages client with the given shared connection handle.
    pub(crate) const fn new(conn: ConnHandle) -> Self {
        Self { conn }
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
        let res = self.conn.make_v2_req(msg).await?;
        let ServerMessage::GetPreimage { preimg } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };
        Ok(preimg)
    }
}
