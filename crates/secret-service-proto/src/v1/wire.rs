use musig2::errors::{RoundContributionError, RoundFinalizeError};
use rkyv::{
    api::high::{to_bytes_in, HighSerializer},
    rancor,
    ser::allocator::ArenaHandle,
    util::AlignedVec,
    with::Map,
    Archive, Deserialize, Serialize,
};

use super::traits::{
    Musig2SessionId, Musig2SignerFirstRound, OperatorSigner, P2PSigner, SecretService, Server,
};

trait WireMessageMarker:
    for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rancor::Error>>
{
}

#[derive(Debug, Clone, Archive, Serialize, Deserialize)]
pub enum ServerMessage<S, SecondRound, FirstRound>
where
    S: SecretService<Server, SecondRound, FirstRound>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
{
    InvalidClientMessage,
    OpaqueServerError,

    OperatorSignPsbt(
        Result<Vec<u8>, <S::OperatorSigner as OperatorSigner<Server>>::OperatorSigningError>,
    ),

    SignP2P(Result<[u8; 64], <S::P2PSigner as P2PSigner<Server>>::P2PSigningError>),

    Musig2NewSession(Musig2SessionId),

    Musig2FirstRoundOurNonce([u8; 66]),
    Musig2FirstRoundHoldouts(Vec<[u8; 33]>),
    Musig2FirstRoundIsComplete(bool),
    Musig2FirstRoundReceivePubNonce(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),
    Musig2FirstRoundFinalize(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundFinalizeError>)] Option<RoundFinalizeError>,
    ),

    Musig2SecondRoundAggNonce([u8; 66]),
    Musig2SecondRoundHoldouts(Vec<[u8; 33]>),
    Musig2SecondRoundOurSignature([u8; 32]),
    Musig2SecondRoundIsComplete(bool),
    Musig2SecondRoundReceiveSignature(
        #[rkyv(with = Map<super::rkyv_wrappers::RoundContributionError>)]
        Option<RoundContributionError>,
    ),
    Musig2SecondRoundFinalize(Musig2SessionResult),

    WotsGetKey([u8; 64]),
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

impl WireMessageMarker for ClientMessage {}

pub trait WireMessage {
    fn serialize(&self) -> Result<AlignedVec, rancor::Error>;
}

// ignore, probably will just directly write to the connection instead of this
impl<T: WireMessageMarker> WireMessage for T {
    fn serialize(&self) -> Result<AlignedVec, rancor::Error> {
        let mut aligned_buf = AlignedVec::new();
        // write a default length
        aligned_buf.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut aligned_buf = to_bytes_in(self, aligned_buf)?;
        let len = aligned_buf.len() - 4;
        debug_assert!(len <= u32::MAX as usize);
        let len_as_le_bytes = (len as u32).to_le_bytes();
        for i in 0..4 {
            aligned_buf[i] = len_as_le_bytes[i]
        }
        Ok(aligned_buf)
    }
}
