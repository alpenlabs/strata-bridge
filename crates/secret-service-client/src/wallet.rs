//! Operator signer client

use std::sync::Arc;

use bitcoin::{hashes::Hash, TapNodeHash, XOnlyPublicKey};
use musig2::secp256k1::schnorr::Signature;
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, Origin, WalletSigner},
    wire::{ClientMessage, ServerMessage},
};

use crate::{make_v1_req, Config};

/// General wallet signer client.
#[derive(Debug, Clone)]
pub struct GeneralWalletClient {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl GeneralWalletClient {
    /// Creates a new operator client with an existing QUIC connection and configuration.
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl WalletSigner<Client> for GeneralWalletClient {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::GeneralWalletSign {
            digest: *digest,
            tweak: tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::GeneralWalletSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn pubkey(&self) -> <Client as Origin>::Container<XOnlyPublicKey> {
        let msg = ClientMessage::GeneralWalletPubkey;
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::GeneralWalletPubkey { pubkey } => {
                XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }
}

/// Stakechain wallet signer client.
#[derive(Debug, Clone)]
pub struct StakechainWalletClient {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl StakechainWalletClient {
    /// Creates a new operator client with an existing QUIC connection and configuration.
    pub fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl WalletSigner<Client> for StakechainWalletClient {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::StakechainWalletSign {
            digest: *digest,
            tweak: tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::StakechainWalletSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn pubkey(&self) -> <Client as Origin>::Container<XOnlyPublicKey> {
        let msg = ClientMessage::StakechainWalletPubkey;
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::StakechainWalletPubkey { pubkey } => {
                XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }
}
