//! Operator signer client
use std::{future::Future, sync::Arc};

use musig2::secp256k1::{schnorr::Signature, PublicKey};
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, OperatorSigner, Origin},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

pub struct OperatorClient {
    conn: Connection,
    config: Arc<Config>,
}

impl OperatorClient {
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl OperatorSigner<Client> for OperatorClient {
    fn sign(
        &self,
        digest: &[u8; 32],
    ) -> impl Future<Output = <Client as Origin>::Container<Signature>> + Send {
        async move {
            let msg = ClientMessage::OperatorSign {
                digest: digest.clone(),
            };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            match res {
                ServerMessage::OperatorSign { sig } => {
                    Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
                }
                _ => Err(ClientError::WrongMessage(res)),
            }
        }
    }

    fn pubkey(&self) -> impl Future<Output = <Client as Origin>::Container<PublicKey>> + Send {
        async move {
            let msg = ClientMessage::OperatorPubkey;
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            match res {
                ServerMessage::OperatorPubkey { pubkey } => {
                    PublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
                }
                _ => Err(ClientError::WrongMessage(res)),
            }
        }
    }
}
