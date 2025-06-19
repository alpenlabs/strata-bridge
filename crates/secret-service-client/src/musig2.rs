//! MuSig2 signer client

use std::sync::Arc;

use bitcoin::{hashes::Hash, TapNodeHash, XOnlyPublicKey};
use musig2::{
    secp256k1::schnorr::Signature, AggNonce, LiftedSignature, PartialSignature, PubNonce,
};
use quinn::Connection;
use secret_service_proto::v2::{
    traits::{
        BadFinalSignature, Client, ClientError, Musig2Params, Musig2Signer, Origin,
        OurPubKeyIsNotInParams, RoundContributionError, SchnorrSigner, SelfVerifyFailed,
    },
    wire::{ClientMessage, ServerMessage, SignerTarget},
};

use crate::{make_v2_req, Config};

/// MuSig2 client.
#[derive(Debug, Clone)]
pub struct Musig2Client {
    /// QUIC connection to the server.
    conn: Connection,

    /// Configuration for the client.
    config: Arc<Config>,
}

impl Musig2Client {
    /// Creates a new MuSig2 client with an existing QUIC connection and configuration.
    pub const fn new(conn: Connection, config: Arc<Config>) -> Self {
        Self { conn, config }
    }
}

impl Musig2Signer<Client> for Musig2Client {
    async fn get_pub_nonce(
        &self,
        params: Musig2Params,
    ) -> <Client as Origin>::Container<Result<PubNonce, OurPubKeyIsNotInParams>> {
        let msg = ClientMessage::Musig2GetPubNonce {
            params: params.into(),
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        if let ServerMessage::Musig2GetPubNonce(res) = res {
            Ok(match res {
                Ok(bs) => Ok(PubNonce::from_bytes(&bs).map_err(|_| ClientError::BadData)?),
                Err(e) => Err(e),
            })
        } else {
            Err(ClientError::WrongMessage(res.into()))
        }
    }

    async fn get_our_partial_sig(
        &self,
        params: Musig2Params,
        aggnonce: AggNonce,
        message: &[u8; 32],
    ) -> <Client as Origin>::Container<
        Result<PartialSignature, terrors::OneOf<(OurPubKeyIsNotInParams, SelfVerifyFailed)>>,
    > {
        let msg = ClientMessage::Musig2GetOurPartialSig {
            params: params.into(),
            aggnonce: aggnonce.serialize(),
            message: *message,
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        if let ServerMessage::Musig2GetOurPartialSig(res) = res {
            Ok(match res {
                Ok(bs) => Ok(PartialSignature::from_slice(&bs).map_err(|_| ClientError::BadData)?),
                Err(e) => Err(e),
            })
        } else {
            Err(ClientError::WrongMessage(res.into()))
        }
    }

    async fn create_signature(
        &self,
        params: Musig2Params,
        pubnonces: Vec<PubNonce>,
        message: &[u8; 32],
        partial_sigs: Vec<PartialSignature>,
    ) -> <Client as Origin>::Container<
        Result<
            LiftedSignature,
            terrors::OneOf<(
                OurPubKeyIsNotInParams,
                SelfVerifyFailed,
                RoundContributionError,
                BadFinalSignature,
            )>,
        >,
    > {
        let msg = ClientMessage::Musig2CreateSignature {
            params: params.into(),
            pubnonces: pubnonces.into_iter().map(|pn| pn.serialize()).collect(),
            message: *message,
            partial_sigs: partial_sigs.into_iter().map(|ps| ps.serialize()).collect(),
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        if let ServerMessage::Musig2CreateSignature(res) = res {
            Ok(match res {
                Ok(bs) => Ok(LiftedSignature::from_bytes(&bs).map_err(|_| ClientError::BadData)?),
                Err(e) => Err(e),
            })
        } else {
            Err(ClientError::WrongMessage(res.into()))
        }
    }
}

impl SchnorrSigner<Client> for Musig2Client {
    async fn sign(
        &self,
        digest: &[u8; 32],
        tweak: Option<TapNodeHash>,
    ) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSign {
            target: SignerTarget::Musig2,
            digest: *digest,
            tweak: tweak.map(|t| t.to_raw_hash().to_byte_array()),
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn sign_no_tweak(&self, digest: &[u8; 32]) -> <Client as Origin>::Container<Signature> {
        let msg = ClientMessage::SchnorrSignerSignNoTweak {
            target: SignerTarget::Musig2,
            digest: *digest,
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        match res {
            ServerMessage::SchnorrSignerSign { sig } => {
                Signature::from_slice(&sig).map_err(|_| ClientError::BadData)
            }
            _ => Err(ClientError::WrongMessage(res.into())),
        }
    }

    async fn pubkey(&self) -> <Client as Origin>::Container<XOnlyPublicKey> {
        let msg = ClientMessage::SchnorrSignerPubkey {
            target: SignerTarget::Musig2,
        };
        let res = make_v2_req(&self.conn, msg, self.config.timeout).await?;
        let ServerMessage::SchnorrSignerPubkey { pubkey } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };

        XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::WrongMessage(res.into()))
    }
}
