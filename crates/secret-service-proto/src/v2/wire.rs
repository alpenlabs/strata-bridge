//! V1 wire protocol
// TODO: change all the hardcoded lengths in here to be calculated at compile time when we upgrade
// our compiler

use bitcoin::{
    hashes::Hash,
    taproot::{ControlBlock, TaprootError},
    OutPoint, ScriptBuf, TapNodeHash, XOnlyPublicKey,
};
use bitvm::signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256};
use rkyv::{Archive, Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;
use terrors::OneOf;

use super::traits::{Musig2Params, OurPubKeyIsNotInParams, SelfVerifyFailed};

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
        /// Serialized Schnorr [`XOnlyPublicKey`](bitcoin::XOnlyPublicKey) for operator signatures.
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

/// Serializable version of [`TaprootWitness`].
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum SerializableTaprootWitness {
    /// Use the keypath spend.
    ///
    /// This only requires the signature for the tweaked internal key and nothing else.
    Key,

    /// Use the script path spend.
    ///
    /// This requires the script being spent from as well as the [`ControlBlock`] in addition to
    /// the elements that fulfill the spending condition in the script.
    Script {
        /// Raw bytes of the [`ScriptBuf`].
        script_buf: Vec<u8>,
        /// Raw bytes of the [`ControlBlock`].
        control_block: Vec<u8>,
    },

    /// Use the keypath spend tweaked with some known hash.
    Tweaked {
        /// Tagged hash used in taproot trees.
        tweak: [u8; 32],
    },
}

impl From<TaprootWitness> for SerializableTaprootWitness {
    fn from(witness: TaprootWitness) -> Self {
        match witness {
            TaprootWitness::Key => SerializableTaprootWitness::Key,
            TaprootWitness::Script {
                script_buf,
                control_block,
            } => SerializableTaprootWitness::Script {
                script_buf: script_buf.into_bytes(),
                control_block: control_block.serialize(),
            },
            TaprootWitness::Tweaked { tweak } => SerializableTaprootWitness::Tweaked {
                tweak: tweak.to_raw_hash().to_byte_array(),
            },
        }
    }
}

impl TryFrom<SerializableTaprootWitness> for TaprootWitness {
    type Error = TaprootError;
    fn try_from(value: SerializableTaprootWitness) -> Result<Self, Self::Error> {
        match value {
            SerializableTaprootWitness::Key => Ok(TaprootWitness::Key),
            SerializableTaprootWitness::Script {
                script_buf,
                control_block,
            } => {
                let script_buf = ScriptBuf::from_bytes(script_buf);
                let control_block = ControlBlock::decode(&control_block)?;
                Ok(TaprootWitness::Script {
                    script_buf,
                    control_block,
                })
            }
            SerializableTaprootWitness::Tweaked { tweak } => Ok(TaprootWitness::Tweaked {
                tweak: TapNodeHash::from_byte_array(tweak),
            }),
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
    pub witness: SerializableTaprootWitness,
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
            witness: From::from(value.witness),
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

        let witness = value.witness.try_into().map_err(OneOf::new)?;

        Ok(Self {
            ordered_pubkeys,
            witness,
            input: value.input,
        })
    }
}
