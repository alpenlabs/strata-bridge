//! Operator signer client

use std::sync::Arc;

use bitcoin::{hashes::Hash, TapNodeHash, XOnlyPublicKey};
use musig2::secp256k1::schnorr::Signature;
use quinn::Connection;
use secret_service_proto::v1::{
    traits::{Client, ClientError, Origin, SchnorrSigner},
    wire::{ClientMessage, ServerMessage, SignerTarget},
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
    pub const fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl SchnorrSigner<Client> for GeneralWalletClient {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSign {
            target: SignerTarget::General,
            digest: *digest,
            tweak: tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSignNoTweak {
            target: SignerTarget::General,
            digest: *digest,
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn pubkey(&self) -> <Client as Origin>::Container<XOnlyPublicKey> {
        let msg = ClientMessage::SchnorrSignerPubkey {
            target: SignerTarget::General,
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerPubkey { pubkey } => {
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
    pub const fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl SchnorrSigner<Client> for StakechainWalletClient {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSign {
            target: SignerTarget::Stakechain,
            digest: *digest,
            tweak: tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSignNoTweak {
            target: SignerTarget::Stakechain,
            digest: *digest,
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn pubkey(&self) -> <Client as Origin>::Container<XOnlyPublicKey> {
        let msg = ClientMessage::SchnorrSignerPubkey {
            target: SignerTarget::Stakechain,
        };
        let res = make_v1_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerPubkey { pubkey } => {
                XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }
}
