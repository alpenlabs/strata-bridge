//! Operator signer client

use bitcoin::{hashes::Hash, TapNodeHash, XOnlyPublicKey};
use musig2::secp256k1::schnorr::Signature;
use secret_service_proto::v2::{
    traits::{Client, ClientError, Origin, SchnorrSigner},
    wire::{ClientMessage, ServerMessage, SignerTarget},
};

use crate::ConnHandle;

/// General wallet signer client.
#[derive(Debug, Clone)]
pub struct GeneralWalletClient {
    /// Shared QUIC connection handle (transparently reconnects on dead-connection errors).
    conn: ConnHandle,
}

impl GeneralWalletClient {
    /// Creates a new general wallet signer client with the given shared connection handle.
    pub(crate) const fn new(conn: ConnHandle) -> Self {
        Self { conn }
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
        let res = self.conn.make_v2_req(msg).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn sign_with_key_tweak(
        &self,
        digest: &[u8; 32],
        key_tweak: &[u8; 32],
        tap_tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSignWithKeyTweak {
            target: SignerTarget::General,
            digest: *digest,
            key_tweak: *key_tweak,
            tap_tweak: tap_tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = self.conn.make_v2_req(msg).await?;
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
        let res = self.conn.make_v2_req(msg).await?;
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
        let res = self.conn.make_v2_req(msg).await?;
        match res {
            ServerMessage::SchnorrSignerPubkey { pubkey } => {
                XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }
}

/// Reserved wallet signer client.
#[derive(Debug, Clone)]
pub struct ReservedWalletClient {
    /// Shared QUIC connection handle (transparently reconnects on dead-connection errors).
    conn: ConnHandle,
}

impl ReservedWalletClient {
    /// Creates a new reserved wallet signer client with the given shared connection handle.
    pub(crate) const fn new(conn: ConnHandle) -> Self {
        Self { conn }
    }
}

impl SchnorrSigner<Client> for ReservedWalletClient {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSign {
            target: SignerTarget::Reserved,
            digest: *digest,
            tweak: tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = self.conn.make_v2_req(msg).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn sign_with_key_tweak(
        &self,
        digest: &[u8; 32],
        key_tweak: &[u8; 32],
        tap_tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSignWithKeyTweak {
            target: SignerTarget::Reserved,
            digest: *digest,
            key_tweak: *key_tweak,
            tap_tweak: tap_tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = self.conn.make_v2_req(msg).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSignNoTweak {
            target: SignerTarget::Reserved,
            digest: *digest,
        };
        let res = self.conn.make_v2_req(msg).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn pubkey(&self) -> <Client as Origin>::Container<XOnlyPublicKey> {
        let msg = ClientMessage::SchnorrSignerPubkey {
            target: SignerTarget::Reserved,
        };
        let res = self.conn.make_v2_req(msg).await?;
        match res {
            ServerMessage::SchnorrSignerPubkey { pubkey } => {
                XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }
}
