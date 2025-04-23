use bitcoin::{OutPoint, XOnlyPublicKey};
use musig2::{secp256k1::Message, LiftedSignature, PartialSignature, PubNonce};
use secret_service_client::SecretServiceClient;
use thiserror::Error;

pub struct MusigSessionManager {
    pub s2_client: SecretServiceClient,
}
impl MusigSessionManager {
    pub fn new(s2_client: SecretServiceClient) -> Self {
        MusigSessionManager { s2_client }
    }

    pub async fn get_nonce(&self, outpoint: OutPoint) -> Result<PubNonce, MusigSessionErr> {
        todo!()
    }

    pub async fn put_nonce(
        &self,
        outpoint: OutPoint,
        sender: XOnlyPublicKey,
        nonce: PubNonce,
    ) -> Result<(), MusigSessionErr> {
        todo!()
    }

    pub async fn get_partial(
        &self,
        outpoint: OutPoint,
        sighash: Message,
    ) -> Result<PartialSignature, MusigSessionErr> {
        todo!()
    }

    pub async fn put_partial(
        &self,
        outpoint: OutPoint,
        sender: XOnlyPublicKey,
        partial: PartialSignature,
    ) -> Result<(), MusigSessionErr> {
        todo!()
    }

    pub async fn get_signature(
        &self,
        outpoint: OutPoint,
    ) -> Result<LiftedSignature, MusigSessionErr> {
        todo!()
    }

    pub fn drop_session(&self, outpoint: OutPoint) {
        todo!()
    }
}

#[derive(Debug, Error)]
pub enum MusigSessionErr {
    /// Errors from failed secret service requests
    #[error("secret service request failed with {0:?}")]
    SecretServiceErr(#[from] secret_service_proto::v1::traits::ClientError),

    /// Outpoint doesn't have an active session
    #[error("outpoint does not have a valid and active session")]
    NotFound,
}
