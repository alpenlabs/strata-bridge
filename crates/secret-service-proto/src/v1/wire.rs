//! V1 wire protocol

use bitcoin::{
    hashes::Hash,
    taproot::{ControlBlock, TaprootError},
    ScriptBuf, TapNodeHash,
};
use musig2::errors::{RoundContributionError, RoundFinalizeError};
use rkyv::{with::Map, Archive, Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

use super::traits::{Musig2SessionId, SignerIdxOutOfBounds};

/// Various messages the server can send to the client.
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum ServerMessage {
    /// The message the client sent was invalid.
    InvalidClientMessage,

    /// The server experienced an unexpected internal error while handling the
    /// request.
    ///
    /// Check the server logs for debugging details.
    OpaqueServerError,

    /// Response for [`OperatorSigner::sign`](super::traits::OperatorSigner::sign).
    OperatorSign {
        /// Schnorr signature for a certain message.
        sig: [u8; 64],
    },

    /// Response for [`OperatorSigner::pubkey`](super::traits::OperatorSigner::pubkey).
    OperatorPubkey {
        /// Serialized Schnorr compressed public key for operator signatures
        pubkey: [u8; 32],
    },

    /// Response for [`P2PSigner::sign`](super::traits::P2PSigner::sign).
    P2PSign {
        /// Schnorr signature of for a certain message.
        sig: [u8; 64],
    },

    /// Response for [`P2PSigner::pubkey`](super::traits::P2PSigner::pubkey).
    P2PPubkey {
        /// Serialized Schnorr compressed public key for P2P signatures
        pubkey: [u8; 32],
    },

    /// Response for [`Musig2Signer::new_session`](super::traits::Musig2Signer::new_session).
    Musig2NewSession(Result<Musig2SessionId, SignerIdxOutOfBounds>),

    /// Response for [`Musig2Signer::pubkey`](super::traits::Musig2Signer::pubkey).
    Musig2Pubkey {
        /// Serialized Schnorr compressed public key for Musig2 signatures
        pubkey: [u8; 32],
    },

    /// Response for
    /// [`Musig2SignerFirstRound::our_nonce`](super::traits::Musig2SignerFirstRound::our_nonce).
    Musig2FirstRoundOurNonce {
        /// Our serialized MuSig2 public nonce for the requested signing session.
        our_nonce: [u8; 66],
    },

    /// Response for
    /// [`Musig2SignerFirstRound::holdouts`](super::traits::Musig2SignerFirstRound::holdouts).
    Musig2FirstRoundHoldouts {
        /// Serialized Schnorr compressed public keys of signers whose pub nonces
        /// we do not have
        pubkeys: Vec<[u8; 32]>,
    },
    /// Response for
    /// [`Musig2SignerFirstRound::is_complete`](super::traits::Musig2SignerFirstRound::is_complete).
    Musig2FirstRoundIsComplete {
        /// Flag indicating whether the MuSig2 first round is complete.
        complete: bool,
    },

    /// Response for
    /// [`Musig2SignerFirstRound::receive_pub_nonce`](super::traits::Musig2SignerFirstRound::receive_pub_nonce).
    Musig2FirstRoundReceivePubNonce(
        /// Error indicating whether the server was unable to process the request.
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),

    /// Response for
    /// [`Musig2SignerFirstRound::finalize`](super::traits::Musig2SignerFirstRound::finalize).
    Musig2FirstRoundFinalize(
        /// Error indicating whether the server was unable to process the request.
        #[rkyv(with = Map<super::rkyv_wrappers::RoundFinalizeError>)]
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
        /// Serialized Schnorr compressed public keys of signers whose partial signatures
        /// we do not have for this signing session
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
    /// [`Musig2SignerSecondRound::receive_signature`](super::traits::Musig2SignerSecondRound::receive_signature).
    Musig2SecondRoundReceiveSignature(
        /// The error that occurred during the signature reception.
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),

    /// Response for
    /// [`Musig2SignerSecondRound::finalize`](super::traits::Musig2SignerSecondRound::finalize).
    Musig2SecondRoundFinalize(Musig2SessionResult),

    /// Response for [`WotsSigner::get_160_key`](super::traits::WotsSigner::get_160_key).
    WotsGet160Key {
        /// A set of 20 byte keys, one for each bit that is committed to.
        key: [u8; 20 * 160],
    },

    /// Response for [`WotsSigner::get_256_key`](super::traits::WotsSigner::get_256_key).
    WotsGet256Key {
        /// A set of 20 byte keys, one for each bit that is committed to.
        key: [u8; 20 * 256],
    },

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
    /// The result of a musig2 session.
    Ok([u8; 64]),

    /// The error that occurred during a musig2 session.
    Err(#[rkyv(with = super::rkyv_wrappers::RoundFinalizeError)] RoundFinalizeError),
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
    /// Request for [`OperatorSigner::sign`](super::traits::OperatorSigner::sign).
    OperatorSign {
        /// The digest of the data the client wants signed.
        digest: [u8; 32],
    },

    /// Request for [`OperatorSigner::pubkey`](super::traits::OperatorSigner::pubkey).
    OperatorPubkey,

    /// Request for [`P2PSigner::sign`](super::traits::P2PSigner::sign).
    P2PSign {
        /// The digest of the data the client wants signed.
        digest: [u8; 32],
    },

    /// Request for [`P2PSigner::pubkey`](super::traits::P2PSigner::pubkey).
    P2PPubkey,

    /// Request for [`Musig2Signer::new_session`](super::traits::Musig2Signer::new_session).
    Musig2NewSession {
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

    /// Request for [`Musig2Signer::pubkey`](super::traits::Musig2Signer::pubkey).
    Musig2Pubkey,

    /// Request for
    /// [`Musig2SignerFirstRound::our_nonce`](super::traits::Musig2SignerFirstRound::our_nonce).
    Musig2FirstRoundOurNonce {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::holdouts`](super::traits::Musig2SignerFirstRound::holdouts)
    Musig2FirstRoundHoldouts {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::is_complete`](super::traits::Musig2SignerFirstRound::is_complete).
    Musig2FirstRoundIsComplete {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for
    /// [`Musig2SignerFirstRound::receive_pub_nonce`](super::traits::Musig2SignerFirstRound::receive_pub_nonce).
    Musig2FirstRoundReceivePubNonce {
        /// Session that this server is requesting for.
        session_id: usize,
        /// The serialized compressed schnorr pubkey of the signer whose pubnonce this is
        pubkey: [u8; 32],
        /// Serialized public nonce
        pubnonce: [u8; 66],
    },

    /// Request for
    /// [`Musig2SignerFirstRound::finalize`](super::traits::Musig2SignerFirstRound::finalize).
    Musig2FirstRoundFinalize {
        /// Session that this server is requesting for.
        session_id: usize,

        /// Digest of message the client is signing.
        digest: [u8; 32],
    },

    /// Request for
    /// [`Musig2SignerSecondRound::agg_nonce`](super::traits::Musig2SignerSecondRound::agg_nonce).
    Musig2SecondRoundAggNonce {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::holdouts`](super::traits::Musig2SignerSecondRound::holdouts).
    Musig2SecondRoundHoldouts {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::our_signature`](super::traits::Musig2SignerSecondRound::our_signature).
    Musig2SecondRoundOurSignature {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::is_complete`](super::traits::Musig2SignerSecondRound::is_complete).
    Musig2SecondRoundIsComplete {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for
    /// [`Musig2SignerSecondRound::receive_signature`](super::traits::Musig2SignerSecondRound::receive_signature).
    Musig2SecondRoundReceiveSignature {
        /// Session that this server is requesting for.
        session_id: usize,
        /// The serialized compressed schnorr pubkey of the signer whose pubnonce this is
        pubkey: [u8; 32],
        /// That signer's musig2 partial sig
        signature: [u8; 32],
    },

    /// Request for
    /// [`Musig2SignerSecondRound::finalize`](super::traits::Musig2SignerSecondRound::finalize).
    Musig2SecondRoundFinalize {
        /// Session that this server is requesting for.
        session_id: usize,
    },

    /// Request for [`WotsSigner::get_160_key`](super::traits::WotsSigner::get_160_key).
    WotsGet160Key {
        /// [`Txid`](bitcoin::Txid) that this WOTS public key is derived from.
        txid: [u8; 32],

        /// Transaction's vout that this WOTS public key is derived from.
        vout: u32,

        /// Transaction's index that this WOTS public key is derived from.
        ///
        /// Some inputs ([`Txid`](bitcoin::Txid) and vout) need more than one WOTS public key,
        /// hence to resolve the ambiguity, the index is needed.
        index: u32,
    },

    /// Request for [`WotsSigner::get_256_key`](super::traits::WotsSigner::get_256_key).
    WotsGet256Key {
        /// [`Txid`](bitcoin::Txid) that this WOTS public key is derived from.
        txid: [u8; 32],

        /// Transaction's vout that this WOTS public key is derived from.
        vout: u32,

        /// Transaction's index that this WOTS public key is derived from.
        ///
        /// Some inputs ([`Txid`](bitcoin::Txid) and vout) need more than one WOTS public key,
        /// hence to resolve the ambiguity, the index is needed.
        index: u32,
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
    Tweaked { tweak: [u8; 32] },
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
