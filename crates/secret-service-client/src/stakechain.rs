//! Stakechain preimages client
use std::{future::Future, sync::Arc};

use bitcoin::{hashes::Hash, Txid};
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, Origin, StakeChainPreimages},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

pub struct StakeChainPreimgClient {
    conn: Connection,
    config: Arc<Config>,
}

impl StakeChainPreimgClient {
    /// Guess?
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl StakeChainPreimages<Client> for StakeChainPreimgClient {
    fn get_preimg(
        &self,
        prestake_txid: Txid,
        prestake_vout: u32,
        stake_index: u32,
    ) -> impl Future<Output = <Client as Origin>::Container<[u8; 32]>> + Send {
        async move {
            let msg = ClientMessage::StakeChainGetPreimage {
                prestake_txid: prestake_txid.to_byte_array(),
                prestake_vout,
                stake_index,
            };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::StakeChainGetPreimage { preimg } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Ok(preimg)
        }
    }
}
