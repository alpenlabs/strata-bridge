//! MuSig2 signer client

use bitcoin::{hashes::Hash, TapNodeHash, XOnlyPublicKey};
use musig2::{secp256k1::schnorr::Signature, AggNonce, PartialSignature, PubNonce};
use secret_service_proto::v2::{
    traits::{
        Client, ClientError, Musig2Params, Musig2Signer, Origin, OurPubKeyIsNotInParams,
        SchnorrSigner, SelfVerifyFailed,
    },
    wire::{ClientMessage, ServerMessage, SignerTarget},
};

use crate::ConnHandle;

/// MuSig2 client.
#[derive(Debug, Clone)]
pub struct Musig2Client {
    /// Shared QUIC connection handle (transparently reconnects on dead-connection errors).
    conn: ConnHandle,
}

impl Musig2Client {
    /// Creates a new MuSig2 client with the given shared connection handle.
    pub(crate) const fn new(conn: ConnHandle) -> Self {
        Self { conn }
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
        let res = self.conn.make_v2_req(msg).await?;
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
    ) -> <Client as Origin>::Container<
        Result<PartialSignature, terrors::OneOf<(OurPubKeyIsNotInParams, SelfVerifyFailed)>>,
    > {
        let msg = ClientMessage::Musig2GetOurPartialSig {
            params: params.into(),
            aggnonce: aggnonce.serialize(),
        };
        let res = self.conn.make_v2_req(msg).await?;
        if let ServerMessage::Musig2GetOurPartialSig(res) = res {
            Ok(match res {
                Ok(bs) => Ok(PartialSignature::from_slice(&bs).map_err(|_| ClientError::BadData)?),
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
            target: SignerTarget::Musig2,
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
            target: SignerTarget::Musig2,
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
            target: SignerTarget::Musig2,
        };
        let res = self.conn.make_v2_req(msg).await?;
        let ServerMessage::SchnorrSignerPubkey { pubkey } = res else {
            return Err(ClientError::WrongMessage(res.into()));
        };

        XOnlyPublicKey::from_slice(&pubkey).map_err(|_| ClientError::WrongMessage(res.into()))
    }
}
