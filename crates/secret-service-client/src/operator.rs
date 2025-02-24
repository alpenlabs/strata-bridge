//! Operator signer client

use std::{future::Future, sync::Arc};

use bitcoin::XOnlyPublicKey;
use musig2::secp256k1::schnorr::Signature;
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, OperatorSigner, Origin},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

/// Operator signer client.
#[derive(Debug, Clone)]
pub struct OperatorClient {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl OperatorClient {
    /// Creates a new operator client with an existing QUIC connection and configuration.
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
            let msg = ClientMessage::OperatorSign { digest: *digest };
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            match res {
                ServerMessage::OperatorSign { sig } => {
                    Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
                }
                _ => Err(ClientError::WrongMessage(res.into())),
            }
        }
    }

    fn pubkey(&self) -> impl Future<Output = <Client as Origin>::Container<XOnlyPublicKey>> + Send {
        async move {
            let msg = ClientMessage::OperatorPubkey;
            let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
            match res {
                ServerMessage::OperatorPubkey { pubkey } => {
                    XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
                }
                _ => Err(ClientError::WrongMessage(res.into())),
            }
        }
    }
}
