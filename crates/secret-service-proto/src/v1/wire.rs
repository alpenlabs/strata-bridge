use musig2::errors::{RoundContributionError, RoundFinalizeError};
use rkyv::{with::Map, Archive, Deserialize, Serialize};

use super::traits::Musig2SessionId;

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum ServerMessage {
    InvalidClientMessage,
    OpaqueServerError,

    OperatorSignPsbt {
        psbt: Vec<u8>,
    },

    SignP2P {
        sig: [u8; 64],
    },
    P2PPubkey {
        pubkey: [u8; 33],
    },

    Musig2NewSession {
        session_id: Musig2SessionId,
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

    WotsGetKey {
        key: [u8; 64],
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
    OperatorSignPsbt {
        psbt: Vec<u8>,
    },

    SignP2P {
        hash: [u8; 32],
    },
    P2PPubkey,

    Musig2NewSession,

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

    WotsGetKey {
        index: u64,
    },
}
