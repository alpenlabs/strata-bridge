//! This module implements a session state management system for musig sessions around a given
//! underlying SecretServiceClient.
use bitcoin::{OutPoint, XOnlyPublicKey};
use musig2::{secp256k1::Message, LiftedSignature, PartialSignature, PubNonce};
use secret_service_client::SecretServiceClient;
use thiserror::Error;

/// System for managing session state for musig sessions.
#[derive(Debug, Clone)]
pub struct MusigSessionManager {
    /// The underlying S2 client.
    pub s2_client: SecretServiceClient,
}
impl MusigSessionManager {
    /// Makes a new MusigSessionManager from a SecretServiceClient.
    pub fn new(s2_client: SecretServiceClient) -> Self {
        MusigSessionManager { s2_client }
    }

    /// Given an OutPoint, get back a PubNonce for that session
    pub async fn get_nonce(&self, outpoint: OutPoint) -> Result<PubNonce, MusigSessionErr> {
        todo!()
    }

    /// Load a PubNonce into the signing session identified by OutPoint.
    pub async fn put_nonce(
        &self,
        outpoint: OutPoint,
        sender: XOnlyPublicKey,
        nonce: PubNonce,
    ) -> Result<(), MusigSessionErr> {
        todo!()
    }

    /// Given an OutPoint and the sighash for what is being signed get our PartialSignature.
    pub async fn get_partial(
        &self,
        outpoint: OutPoint,
        sighash: Message,
    ) -> Result<PartialSignature, MusigSessionErr> {
        todo!()
    }

    /// Load a PartialSignature into the signing session identified by OutPoint.
    pub async fn put_partial(
        &self,
        outpoint: OutPoint,
        sender: XOnlyPublicKey,
        partial: PartialSignature,
    ) -> Result<(), MusigSessionErr> {
        todo!()
    }

    /// Finalize the musig signing process and extract the final LiftedSignature
    pub async fn get_signature(
        &self,
        outpoint: OutPoint,
    ) -> Result<LiftedSignature, MusigSessionErr> {
        todo!()
    }

    /// Delete all session state associated with the given OutPoint.
    pub fn drop_session(&self, outpoint: OutPoint) {
        todo!()
    }
}

/// Error type that encapsulates all of the things that can go wrong with the Musig signing process.
#[derive(Debug, Error)]
pub enum MusigSessionErr {
    /// Errors from failed secret service requests
    #[error("secret service request failed with {0:?}")]
    SecretServiceErr(#[from] secret_service_proto::v1::traits::ClientError),

    /// Outpoint doesn't have an active session
    #[error("outpoint does not have a valid and active session")]
    NotFound,
}
