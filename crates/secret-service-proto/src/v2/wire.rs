//! V2 wire protocol
// TODO: change all the hardcoded lengths in here to be calculated at compile time when we upgrade
// our compiler

use bitcoin::{taproot::TaprootError, OutPoint, XOnlyPublicKey};
use bitvm::signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256};
use rkyv::{Archive, Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::TaprootTweak;
use terrors::OneOf;

use super::traits::{Musig2Params, OurPubKeyIsNotInParams, SelfVerifyFailed};
use crate::v2::rkyv_wrappers;

/// Various messages the server can send to the client.
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ServerMessage {
    /// The message the client sent was invalid, with reasoning
    InvalidClientMessage(String),

    /// The client violated the protocol, with reasoning
    ProtocolError(String),

    /// The server experienced an unexpected internal error while handling the
    /// request.
    ///
    /// Check the server logs for debugging details.
    OpaqueServerError,

    /// An explicit signal from the the server that the client should immediately retry the request
    TryAgain,

    /// Response for [`SchnorrSigner::sign`](super::traits::SchnorrSigner::sign) and
    /// [`SchnorrSigner::sign_no_tweak`](super::traits::SchnorrSigner::sign_no_tweak)
    SchnorrSignerSign {
        /// Schnorr signature for a certain message.
        sig: [u8; 64],
    },

    /// Response for [`SchnorrSigner::pubkey`](super::traits::SchnorrSigner::pubkey).
    SchnorrSignerPubkey {
        /// Serialized Schnorr [`XOnlyPublicKey`] for operator signatures.
        pubkey: [u8; 32],
    },

    /// Response for [`P2PSigner::secret_key`](super::traits::P2PSigner::secret_key).
    P2PSecretKey {
        /// Serialized [`SecretKey`](bitcoin::secp256k1::SecretKey)
        key: [u8; 32],
    },

    /// Response for [`Musig2Signer::get_pub_nonce`](super::traits::Musig2Signer::get_pub_nonce).
    Musig2GetPubNonce(Result<[u8; 66], OurPubKeyIsNotInParams>),

    /// Response for
    /// [`Musig2Signer::get_our_partial_sig`](super::traits::Musig2Signer::get_our_partial_sig).
    Musig2GetOurPartialSig(Result<[u8; 32], OneOf<(OurPubKeyIsNotInParams, SelfVerifyFailed)>>),

    /// Response for

    /// [`WotsSigner::get_128_secret_key`](super::traits::WotsSigner::get_128_secret_key).
    WotsGet128SecretKey {
        /// A set of 20 byte keys, one for each bit that is committed to.
        key: [u8; 720], // 20*36
    },

    /// Response for
    /// [`WotsSigner::get_256_secret_key`](super::traits::WotsSigner::get_256_secret_key).
    WotsGet256SecretKey {
        /// A set of 20 byte keys, one for each bit that is committed to.
        key: [u8; 1360], // 20*68
    },

    /// Response for
    /// [`WotsSigner::get_128_public_key`](super::traits::WotsSigner::get_128_public_key).
    WotsGet128PublicKey {
        /// A set of 20 byte keys, one for each bit that is committed to.
        key: [u8; 720], // 20*36
    },

    /// Response for
    /// [`WotsSigner::get_256_public_key`](super::traits::WotsSigner::get_256_public_key).
    WotsGet256PublicKey {
        /// A set of 20 byte keys, one for each bit that is committed to.
        key: [u8; 1360], // 20*68
    },

    /// Response for
    /// [`WotsSigner::get_128_signature`](super::traits::WotsSigner::get_128_signature).
    WotsGet128Signature { sig: <wots_hash as Wots>::Signature },

    /// Response for
    /// [`WotsSigner::get_256_signature`](super::traits::WotsSigner::get_256_signature).
    WotsGet256Signature { sig: <wots256 as Wots>::Signature },

    /// Response for
    /// [`StakeChainPreimages::get_preimg`](super::traits::StakeChainPreimages::get_preimg).
    StakeChainGetPreimage {
        /// The preimage that was requested.
        preimg: [u8; 32],
    },
}

/// Various messages the client can send to the server.
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Request for [`P2PSigner::secret_key`](super::traits::P2PSigner::secret_key).
    P2PSecretKey,

    /// Request for [`SchnorrSigner::sign`](super::traits::SchnorrSigner::sign).
    SchnorrSignerSign {
        /// Which Schnorr key to use
        target: SignerTarget,

        /// The digest of the data the client wants signed.
        digest: [u8; 32],

        /// The tweak used to sign the message.
        tweak: Option<[u8; 32]>,
    },

    /// Request for [`SchnorrSigner::sign_no_tweak`](super::traits::SchnorrSigner::sign_no_tweak).
    SchnorrSignerSignNoTweak {
        /// Which Schnorr key to use
        target: SignerTarget,

        /// The digest of the data the client wants signed.
        digest: [u8; 32],
    },

    /// Request for [`SchnorrSigner::pubkey`](super::traits::SchnorrSigner::pubkey).
    SchnorrSignerPubkey {
        /// Which Schnorr key to use
        target: SignerTarget,
    },

    /// Request for [`Musig2Signer::get_pub_nonce`](super::traits::Musig2Signer::get_pub_nonce).
    Musig2GetPubNonce {
        /// Params for the musig2 session
        params: SerializableMusig2Params,
    },

    /// Request for
    /// [`Musig2Signer::get_our_partial_sig`](super::traits::Musig2Signer::get_our_partial_sig).
    Musig2GetOurPartialSig {
        /// Params for the musig2 session
        params: SerializableMusig2Params,
        /// Aggregated nonce from round 1
        aggnonce: [u8; 66],
        /// Message to be signed
        message: [u8; 32],
    },

    /// Request for
    /// [`WotsSigner::get_128_secret_key`](super::traits::WotsSigner::get_128_secret_key).
    WotsGet128SecretKey {
        /// Specifier for which WOTS key to use
        specifier: WotsKeySpecifier,
    },

    /// Request for
    /// [`WotsSigner::get_256_secret_key`](super::traits::WotsSigner::get_256_secret_key).
    WotsGet256SecretKey {
        /// Specifier for which WOTS key to use
        specifier: WotsKeySpecifier,
    },

    /// Request for
    /// [`WotsSigner::get_128_public_key`](super::traits::WotsSigner::get_128_public_key).
    WotsGet128PublicKey {
        /// Specifier for which WOTS key to use
        specifier: WotsKeySpecifier,
    },

    /// Request for
    /// [`WotsSigner::get_256_public_key`](super::traits::WotsSigner::get_256_public_key).
    WotsGet256PublicKey {
        /// Specifier for which WOTS key to use
        specifier: WotsKeySpecifier,
    },

    /// Request for
    /// [`WotsSigner::get_128_signature`](super::traits::WotsSigner::get_128_signature).
    WotsGet128Signature {
        /// Specifier for which WOTS key to use
        specifier: WotsKeySpecifier,

        /// 128-bit message to be signed.
        msg: [u8; 16],
    },

    /// Request for
    /// [`WotsSigner::get_256_signature`](super::traits::WotsSigner::get_256_signature).
    WotsGet256Signature {
        /// Specifier for which WOTS key to use
        specifier: WotsKeySpecifier,

        /// 256-bit message to be signed.
        msg: [u8; 32],
    },

    /// Request for
    /// [`StakeChainPreimages::get_preimg`](super::traits::StakeChainPreimages::get_preimg).
    StakeChainGetPreimage {
        /// The Pre-Stake [`Txid`](bitcoin::Txid) that this Stake Chain preimage is derived from.
        prestake_txid: [u8; 32],

        /// The Pre-Stake transaction's vout that this Stake Chain preimage is derived from.
        prestake_vout: u32,

        /// Stake index that this Stake Chain preimage is derived from.
        stake_index: u32,
    },
}

/// Serializable version of [`TaprootTweak`].
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum SerializableTaprootTweak {
    Key {
        tweak: Option<rkyv_wrappers::TapNodeHash>,
    },
    Script,
}

impl From<SerializableTaprootTweak> for TaprootTweak {
    fn from(value: SerializableTaprootTweak) -> Self {
        match value {
            SerializableTaprootTweak::Key { tweak } => TaprootTweak::Key {
                tweak: tweak.map(|t| t.into()),
            },
            SerializableTaprootTweak::Script => TaprootTweak::Script,
        }
    }
}

impl From<TaprootTweak> for SerializableTaprootTweak {
    fn from(value: TaprootTweak) -> Self {
        match value {
            TaprootTweak::Key { tweak } => SerializableTaprootTweak::Key {
                tweak: tweak.map(|t| t.into()),
            },
            TaprootTweak::Script => SerializableTaprootTweak::Script,
        }
    }
}

#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize)]
pub enum SignerTarget {
    General,
    Stakechain,
    Musig2,
}

#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize)]
pub struct WotsKeySpecifier {
    /// [`Txid`](bitcoin::Txid) that the WOTS key is derived from.
    pub txid: [u8; 32],

    /// Transaction's vout that the WOTS key is derived from.
    pub vout: u32,

    /// WOTS index that the WOTS key is derived from.
    ///
    /// Some inputs ([`Txid`](bitcoin::Txid) and vout) need more than one WOTS signature,
    /// hence to resolve the ambiguity, the index is needed.
    pub index: u32,
}

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub struct SerializableMusig2Params {
    pub ordered_pubkeys: Vec<[u8; 32]>,
    pub tweak: SerializableTaprootTweak,
    #[rkyv(with = super::rkyv_wrappers::OutPoint)]
    pub input: OutPoint,
}

impl From<Musig2Params> for SerializableMusig2Params {
    fn from(value: Musig2Params) -> Self {
        Self {
            ordered_pubkeys: value
                .ordered_pubkeys
                .iter()
                .map(|pk| pk.serialize())
                .collect(),
            tweak: From::from(value.tweak),
            input: value.input,
        }
    }
}

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub struct InvalidPublicKey;

impl TryFrom<SerializableMusig2Params> for Musig2Params {
    type Error = OneOf<(InvalidPublicKey, TaprootError)>;

    fn try_from(value: SerializableMusig2Params) -> Result<Self, Self::Error> {
        let ordered_pubkeys = value
            .ordered_pubkeys
            .into_iter()
            .map(|pk| XOnlyPublicKey::from_slice(&pk))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| OneOf::new(InvalidPublicKey))?;

        Ok(Self {
            ordered_pubkeys,
            tweak: value.tweak.into(),
            input: value.input,
        })
    }
}
