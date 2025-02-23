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
    /// request. Check the server logs for debugging details.
    OpaqueServerError,

    /// Response for OperatorSigner::sign
    OperatorSign {
        /// Schnorr signature of provided digest
        sig: [u8; 64],
    },
    /// Response for OperatorSigner::pubkey
    OperatorPubkey {
        /// Serialized Schnorr compressed public key for operator signatures
        pubkey: [u8; 32],
    },

    /// Response for P2PSigner::sign
    P2PSign {
        /// Schnorr signature of provided digest
        sig: [u8; 64],
    },
    /// Response for P2PSigner::pubkey
    P2PPubkey {
        /// Serialized Schnorr compressed public key for P2P signatures
        pubkey: [u8; 32],
    },

    /// Response for Musig2Signer::new_session
    Musig2NewSession(Result<Musig2SessionId, SignerIdxOutOfBounds>),
    /// Response for Musig2Signer::pubkey
    Musig2Pubkey {
        /// Serialized Schnorr compressed public key for Musig2 signatures
        pubkey: [u8; 32],
    },

    /// Response for Musig2SignerFirstRound::our_nonce
    Musig2FirstRoundOurNonce {
        /// Our serialized musig2 public nonce for the requested signing session
        our_nonce: [u8; 66],
    },
    /// Response for Musig2SignerFirstRound::holdouts
    Musig2FirstRoundHoldouts {
        /// Serialized Schnorr compressed public keys of signers whose pub nonces
        /// we do not have
        pubkeys: Vec<[u8; 32]>,
    },
    /// Response for Musig2SignerFirstRound::is_complete
    Musig2FirstRoundIsComplete {
        /// What do you think it means?
        complete: bool,
    },
    /// Response for Musig2SignerFirstRound::receive_pub_nonce
    Musig2FirstRoundReceivePubNonce(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),
    /// Response for Musig2SignerFirstRound::finalize
    Musig2FirstRoundFinalize(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundFinalizeError>)] Option<RoundFinalizeError>,
    ),

    /// Response for Musig2SignerSecondRound::agg_nonce
    Musig2SecondRoundAggNonce {
        /// Serialized aggregated nonce of the signing session's first round
        nonce: [u8; 66],
    },
    /// Response for Musig2SignerSecondRound::holdouts
    Musig2SecondRoundHoldouts {
        /// Serialized Schnorr compressed public keys of signers whose partial signatures
        /// we do not have for this signing session
        pubkeys: Vec<[u8; 32]>,
    },
    /// Response for Musig2SignerSecondRound::our_signature
    Musig2SecondRoundOurSignature {
        /// Our serialized partial signature of the signing session
        sig: [u8; 32],
    },
    /// Response for Musig2SignerSecondRound::is_complete
    Musig2SecondRoundIsComplete {
        /// Hmm. I wonder what this could mean.
        complete: bool,
    },
    /// Response for Musig2SignerSecondRound::receive_signature
    Musig2SecondRoundReceiveSignature(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),
    /// Response for Musig2SignerSecondRound::finalize
    Musig2SecondRoundFinalize(Musig2SessionResult),

    /// Response for WotsSigner::get_160_key
    WotsGet160Key {
        /// A set of 20 byte keys, one for each bit
        key: [u8; 20 * 160],
    },
    /// Response for WotsSigner::get_256_key
    WotsGet256Key {
        /// A set of 20 byte keys, one for each bit
        key: [u8; 20 * 256],
    },

    /// Response for StakeChainPreimages::get_preimg
    StakeChainGetPreimage {
        /// The preimage you asked for?
        preimg: [u8; 32],
    },
}

/// Helper type for serialization
/// Maybe replaced with a future rkyv::with::MapRes or smth?
#[allow(missing_docs)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum Musig2SessionResult {
    Ok([u8; 64]),
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

// impl<SS: SecretService<Server>> WireMessageMarker for ServerMessage<SS> {}

/// Various messages the client can send to the server.
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Request for OperatorSigner::sign
    OperatorSign {
        /// The digest of the data we want signed
        digest: [u8; 32],
    },
    /// Request for OperatorSigner::pubkey
    OperatorPubkey,

    /// Request for P2PSigner::sign
    P2PSign {
        /// The digest of the data we want signed
        digest: [u8; 32],
    },
    /// Request for P2PSigner::pubkey
    P2PPubkey,

    /// Request for Musig2Signer::new_session
    Musig2NewSession {
        /// Public keys for the signing session. May or may not include our own
        /// public key. If not present, it should be added. May or may not be sorted.
        pubkeys: Vec<[u8; 32]>,
        /// The taproot witness of the input
        witness: SerializableTaprootWitness,
        /// Serialized txid of the input tx
        input_txid: [u8; 32],
        /// The vout of the input tx we're signing for (i think?)
        input_vout: u32,
    },
    /// Request for Musig2Signer::pubkey
    Musig2Pubkey,

    /// Request for Musig2SignerFirstRound::our_nonce
    Musig2FirstRoundOurNonce {
        /// Session that we're requesting for
        session_id: usize,
    },
    /// Request for Musig2SignerFirstRound::holdouts
    Musig2FirstRoundHoldouts {
        /// Session that we're requesting for
        session_id: usize,
    },
    /// Request for Musig2SignerFirstRound::is_complete
    Musig2FirstRoundIsComplete {
        /// Session that we're requesting for
        session_id: usize,
    },
    /// Request for Musig2SignerFirstRound::receive_pub_nonce
    Musig2FirstRoundReceivePubNonce {
        /// Session that we're requesting for
        session_id: usize,
        /// The serialized compressed schnorr pubkey of the signer whose pubnonce this is
        pubkey: [u8; 32],
        /// Serialized public nonce
        pubnonce: [u8; 66],
    },
    /// Request for Musig2SignerFirstRound::finalize
    Musig2FirstRoundFinalize {
        /// Session that we're requesting for
        session_id: usize,
        /// Digest of message we're signing
        digest: [u8; 32],
    },

    /// Request for Musig2SignerSecondRound::agg_nonce
    Musig2SecondRoundAggNonce {
        /// Session that we're requesting for
        session_id: usize,
    },
    /// Request for Musig2SignerSecondRound::holdouts
    Musig2SecondRoundHoldouts {
        /// Session that we're requesting for
        session_id: usize,
    },
    /// Request for Musig2SignerSecondRound::our_signature
    Musig2SecondRoundOurSignature {
        /// Session that we're requesting for
        session_id: usize,
    },
    /// Request for Musig2SignerSecondRound::is_complete
    Musig2SecondRoundIsComplete {
        /// Session that we're requesting for
        session_id: usize,
    },
    /// Request for Musig2SignerSecondRound::receive_signature
    Musig2SecondRoundReceiveSignature {
        /// Session that we're requesting for
        session_id: usize,
        /// The serialized compressed schnorr pubkey of the signer whose pubnonce this is
        pubkey: [u8; 32],
        /// That signer's musig2 partial sig
        signature: [u8; 32],
    },
    /// Request for Musig2SignerSecondRound::finalize
    Musig2SecondRoundFinalize {
        /// Session that we're requesting for
        session_id: usize,
    },

    /// Request for WotsSigner::get_160_key
    WotsGet160Key {
        /// Transaction index (?) opaque
        index: u32,
        /// Transaction vout (?) opaque
        vout: u32,
        /// Transaction txid (?) opaque
        txid: [u8; 32],
    },
    /// Request for WotsSigner::get_256_key
    WotsGet256Key {
        /// Transaction index (?) opaque
        index: u32,
        /// Transaction vout (?) opaque
        vout: u32,
        /// Transaction txid (?) opaque
        txid: [u8; 32],
    },

    /// Request for StakeChainPreimages::get_preimg
    StakeChainGetPreimage {
        /// Transaction txid (?) opaque
        prestake_txid: [u8; 32],
        /// Transaction vout (?) opaque
        prestake_vout: u32,
        /// Stake index (?) opaque
        stake_index: u32,
    },
}

/// Serializable version of [`TaprootWitness`]
#[allow(missing_docs)]
#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum SerializableTaprootWitness {
    Key,
    Script {
        script_buf: Vec<u8>,
        control_block: Vec<u8>,
    },
    Tweaked {
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
