use bitcoin::{
    hashes::Hash,
    taproot::{ControlBlock, TaprootError},
    ScriptBuf, TapNodeHash,
};
use musig2::errors::{RoundContributionError, RoundFinalizeError};
use rkyv::{with::Map, Archive, Deserialize, Serialize};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

use super::traits::{Musig2SessionId, SignerIdxOutOfBounds};

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum ServerMessage {
    InvalidClientMessage,
    OpaqueServerError,

    OperatorSignPsbt {
        sig: [u8; 64],
    },
    OperatorPubkey {
        pubkey: [u8; 33],
    },

    SignP2P {
        sig: [u8; 64],
    },
    P2PPubkey {
        pubkey: [u8; 33],
    },

    Musig2NewSession(Result<Musig2SessionId, SignerIdxOutOfBounds>),
    Musig2Pubkey {
        pubkey: [u8; 33],
    },

    Musig2FirstRoundOurNonce {
        our_nonce: [u8; 66],
    },
    Musig2FirstRoundHoldouts {
        pubkeys: Vec<[u8; 33]>,
    },
    Musig2FirstRoundIsComplete {
        complete: bool,
    },
    Musig2FirstRoundReceivePubNonce(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),
    Musig2FirstRoundFinalize(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundFinalizeError>)] Option<RoundFinalizeError>,
    ),

    Musig2SecondRoundAggNonce {
        nonce: [u8; 66],
    },
    Musig2SecondRoundHoldouts {
        pubkeys: Vec<[u8; 33]>,
    },
    Musig2SecondRoundOurSignature {
        sig: [u8; 32],
    },
    Musig2SecondRoundIsComplete {
        complete: bool,
    },
    Musig2SecondRoundReceiveSignature(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),
    Musig2SecondRoundFinalize(Musig2SessionResult),

    WotsGet160Key {
        key: [u8; 20 * 160],
    },
    WotsGet256Key {
        key: [u8; 20 * 256],
    },

    StakeChainGetPreimage {
        preimg: [u8; 32],
    },
}

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

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum ClientMessage {
    OperatorSign {
        digest: [u8; 32],
    },
    OperatorPubkey,

    P2PSign {
        digest: [u8; 32],
    },
    P2PPubkey,

    Musig2NewSession {
        pubkeys: Vec<[u8; 33]>,
        witness: SerializableTaprootWitness,
    },
    Musig2Pubkey,

    Musig2FirstRoundOurNonce {
        session_id: usize,
    },
    Musig2FirstRoundHoldouts {
        session_id: usize,
    },
    Musig2FirstRoundIsComplete {
        session_id: usize,
    },
    Musig2FirstRoundReceivePubNonce {
        session_id: usize,
        pubkey: [u8; 33],
        pubnonce: [u8; 66],
    },
    Musig2FirstRoundFinalize {
        session_id: usize,
        hash: [u8; 32],
    },

    Musig2SecondRoundAggNonce {
        session_id: usize,
    },
    Musig2SecondRoundHoldouts {
        session_id: usize,
    },
    Musig2SecondRoundOurSignature {
        session_id: usize,
    },
    Musig2SecondRoundIsComplete {
        session_id: usize,
    },
    Musig2SecondRoundReceiveSignature {
        session_id: usize,
        pubkey: [u8; 33],
        signature: [u8; 32],
    },
    Musig2SecondRoundFinalize {
        session_id: usize,
    },

    WotsGet160Key {
        index: u32,
        vout: u32,
        txid: [u8; 32],
    },
    WotsGet256Key {
        index: u32,
        vout: u32,
        txid: [u8; 32],
    },

    StakeChainGetPreimage {
        prestake_txid: [u8; 32],
        prestake_vout: u32,
        stake_index: u32,
    },
}

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

pub enum TaprootWitnessError {
    InvalidWitnessType,
    InvalidScriptControlBlock(TaprootError),
}

impl TryFrom<SerializableTaprootWitness> for TaprootWitness {
    type Error = TaprootWitnessError;
    fn try_from(value: SerializableTaprootWitness) -> Result<Self, Self::Error> {
        match value {
            SerializableTaprootWitness::Key => Ok(TaprootWitness::Key),
            SerializableTaprootWitness::Script {
                script_buf,
                control_block,
            } => {
                let script_buf = ScriptBuf::from_bytes(script_buf);
                let control_block = ControlBlock::decode(&control_block)
                    .map_err(TaprootWitnessError::InvalidScriptControlBlock)?;
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
