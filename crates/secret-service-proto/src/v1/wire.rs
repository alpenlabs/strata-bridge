//! V1 wire protocol
// TODO: change all the hardcoded lengths in here to be calculated at compile time when we upgrade
// our compiler
use std::collections::BTreeMap;

use bitcoin::{
    hashes::Hash,
    taproot::{ControlBlock, TaprootError},
    ScriptBuf, TapNodeHash,
};
use bitvm::signatures::{Wots, Wots16 as wots_hash, Wots32 as wots256};
use musig2::errors::{RoundContributionError, RoundFinalizeError};
use rkyv::{
    with::{Identity, Map, MapKV},
    Archive, Deserialize, Serialize,
};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

use super::{
    rkyv_wrappers,
    traits::{Musig2SessionId, SignerIdxOutOfBounds},
};

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

    /// Response for [`Musig2Signer::new_session`](super::traits::Musig2Signer::new_session).
    Musig2NewSession(Result<(), Musig2NewSessionError>),

    /// Response for
    /// [`Musig2SignerFirstRound::our_nonce`](super::traits::Musig2SignerFirstRound::our_nonce).
    Musig2FirstRoundOurNonce {
        /// Our serialized MuSig2 public nonce for the requested signing session.
        our_nonce: [u8; 66],
    },

    /// Response for
    /// [`Musig2SignerFirstRound::holdouts`](super::traits::Musig2SignerFirstRound::holdouts).
    Musig2FirstRoundHoldouts {
        /// Serialized Schnorr [`XOnlyPublicKey`](bitcoin::XOnlyPublicKey) of signers whose public
        /// nonces we do not have.
        pubkeys: Vec<[u8; 32]>,
    },
    /// Response for
    /// [`Musig2SignerFirstRound::is_complete`](super::traits::Musig2SignerFirstRound::is_complete).
    Musig2FirstRoundIsComplete {
        /// Flag indicating whether the MuSig2 first round is complete.
        complete: bool,
    },

    /// Response for
    /// [`Musig2SignerFirstRound::receive_pub_nonces`](super::traits::Musig2SignerFirstRound::receive_pub_nonces).
    Musig2FirstRoundReceivePubNonce(
        /// Errors indicating whether the server was unable to process the request, indexed by the
        /// pubnonce's signer's xonly pubkey. If empty, should be returned as a Ok(())
        #[rkyv(with = MapKV<Identity, rkyv_wrappers::RoundContributionError>)]
        BTreeMap<[u8; 32], RoundContributionError>,
    ),

    /// Response for
    /// [`Musig2SignerFirstRound::finalize`](super::traits::Musig2SignerFirstRound::finalize).
    Musig2FirstRoundFinalize(
        /// Error indicating whether the server was unable to process the request.
        #[rkyv(with = Map<rkyv_wrappers::RoundFinalizeError>)]
        Option<RoundFinalizeError>,
    ),

    /// Response for
    /// [`Musig2SignerSecondRound::agg_nonce`](super::traits::Musig2SignerSecondRound::agg_nonce).
    Musig2SecondRoundAggNonce {
        /// Serialized aggregated public nonce of the signing session's first round.
        nonce: [u8; 66],
    },

    /// Response for
    /// [`Musig2SignerSecondRound::holdouts`](super::traits::Musig2SignerSecondRound::holdouts).
    Musig2SecondRoundHoldouts {
        /// Serialized Schnorr [`XOnlyPublicKey`](bitcoin::XOnlyPublicKey) of signers whose partial
        /// signatures we do not have for this signing session.
        pubkeys: Vec<[u8; 32]>,
    },

    /// Response for
    /// [`Musig2SignerSecondRound::our_signature`](super::traits::Musig2SignerSecondRound::our_signature).
    Musig2SecondRoundOurSignature {
        /// This server's serialized partial signature of the signing session.
        sig: [u8; 32],
    },

    /// Response for
    /// [`Musig2SignerSecondRound::is_complete`](super::traits::Musig2SignerSecondRound::is_complete).
    Musig2SecondRoundIsComplete {
        /// Flag indicating whether the MuSig2 second round is complete.
        complete: bool,
    },

    /// Response for
    /// [`Musig2SignerSecondRound::receive_signatures`](super::traits::Musig2SignerSecondRound::receive_signatures).
    Musig2SecondRoundReceiveSignature(
        /// Any errors that occurred during signature reception, keyed by the partial signature's
        /// signer's xonly pubkey If empty, should be returned as a Ok(())
        #[rkyv(with = MapKV<Identity, rkyv_wrappers::RoundContributionError>)]
        BTreeMap<[u8; 32], RoundContributionError>,
    ),

    /// Response for
    /// [`Musig2SignerSecondRound::finalize`](super::traits::Musig2SignerSecondRound::finalize).
    Musig2SecondRoundFinalize(Musig2SessionResult),

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

/// Helper type for serialization.
// TODO: Maybe replaced with a future rkyv::with::MapRes or smth?
#[allow(missing_docs)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum Musig2SessionResult {
    /// The result of a MuSig2 session.
    Ok([u8; 64]),

    /// The error that occurred during a MuSig2 session.
    Err(#[rkyv(with = rkyv_wrappers::RoundFinalizeError)] RoundFinalizeError),
}

impl From<Result<[u8; 64], RoundFinalizeError>> for Musig2SessionResult {
    fn from(value: Result<[u8; 64], RoundFinalizeError>) -> Self {
        match value {
            Ok(v) => Self::Ok(v),
            Err(v) => Self::Err(v),
        }
    }
}

impl From<Musig2SessionResult> for Result<[u8; 64], RoundFinalizeError> {
    fn from(value: Musig2SessionResult) -> Self {
        match value {
            Musig2SessionResult::Ok(v) => Ok(v),
            Musig2SessionResult::Err(v) => Err(v),
        }
    }
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

    /// Request for [`Musig2Signer::new_session`](super::traits::Musig2Signer::new_session).
    Musig2NewSession {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,

        /// Public keys for the signing session. May or may not include our own
        /// public key. If not present, it should be added. May or may not be sorted.
        pubkeys: Vec<[u8; 32]>,

        /// The taproot witness of the input
        witness: SerializableTaprootWitness,

        /// Serialized [`Txid`](bitcoin::Txid) of the input transaction ID.
        input_txid: [u8; 32],

        /// The vout of the input transaction the client is signing for.
        input_vout: u32,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::our_nonce`](super::traits::Musig2SignerFirstRound::our_nonce).
    Musig2FirstRoundOurNonce {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::holdouts`](super::traits::Musig2SignerFirstRound::holdouts)
    Musig2FirstRoundHoldouts {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::is_complete`](super::traits::Musig2SignerFirstRound::is_complete).
    Musig2FirstRoundIsComplete {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::receive_pub_nonces`](super::traits::Musig2SignerFirstRound::receive_pub_nonces).
    Musig2FirstRoundReceivePubNonce {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,

        /// Public nonces keyed by the signer's xonly public key
        nonces: BTreeMap<[u8; 32], [u8; 66]>,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::finalize`](super::traits::Musig2SignerFirstRound::finalize).
    Musig2FirstRoundFinalize {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,

        /// Digest of message the client is signing.
        digest: [u8; 32],
    },

    /// Request for
    /// [`Musig2SignerSecondRound::agg_nonce`](super::traits::Musig2SignerSecondRound::agg_nonce).
    Musig2SecondRoundAggNonce {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::holdouts`](super::traits::Musig2SignerSecondRound::holdouts).
    Musig2SecondRoundHoldouts {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::our_signature`](super::traits::Musig2SignerSecondRound::our_signature).
    Musig2SecondRoundOurSignature {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::is_complete`](super::traits::Musig2SignerSecondRound::is_complete).
    Musig2SecondRoundIsComplete {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::receive_signatures`](super::traits::Musig2SignerSecondRound::receive_signatures).
    Musig2SecondRoundReceiveSignature {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
        /// Partial signatures, keyed by the signer's xonly public key
        sigs: BTreeMap<[u8; 32], [u8; 32]>,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::finalize`](super::traits::Musig2SignerSecondRound::finalize).
    Musig2SecondRoundFinalize {
        /// Session that this server is requesting for.
        #[rkyv(with = rkyv_wrappers::OutPoint)]
        session_id: Musig2SessionId,
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

/// Error enum around the musig2 new session errors
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum Musig2NewSessionError {
    SignerIdxOutOfBounds(SignerIdxOutOfBounds),
    SessionAlreadyPresent,
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
