//! P2P signer client
use std::{future::Future, sync::Arc};

use musig2::secp256k1::{schnorr::Signature, PublicKey};
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, Origin, P2PSigner},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

pub struct P2PClient {
    conn: Connection,
    config: Arc<Config>,
}

impl P2PClient {
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
            let msg = ClientMessage::P2PSign {
                digest: digest.clone(),
            };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::P2PSign { sig } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
        }
    }

    fn pubkey(&self) -> impl Future<Output = <Client as Origin>::Container<PublicKey>> + Send {
        async move {
            let msg = ClientMessage::P2PPubkey;
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            let ServerMessage::P2PPubkey { pubkey } = res else {
                return Err(ClientError::WrongMessage(res));
            };
            PublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
        }
    }
}
