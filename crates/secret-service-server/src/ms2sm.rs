use std::{mem::MaybeUninit, sync::Arc};

use musig2::{errors::RoundFinalizeError, LiftedSignature};
use secret_service_proto::v1::traits::{Musig2SignerFirstRound, Musig2SignerSecondRound, Server};
use terrors::OneOf;

use crate::bool_arr::DoubleBoolArray;

pub struct Musig2SessionManager<FirstRound, SecondRound, const N: usize = 128>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
{
    /// Tracker is used for tracking whether a session is in first round,
    /// second round or completed. N=128 means we can track 128*32=4096 sessions
    tracker: DoubleBoolArray<N, SlotState>,
    /// Used to store first rounds of musig2 server instances. This is a Vec
    /// because we don't know how big FirstRound may be in memory so we will
    /// heap allocate and try keep this to a minimum
    first_rounds: Vec<MaybeUninit<Arc<FirstRound>>>,
    /// Used to store second rounds of musig2 server instances. This is a Vec
    /// because we don't know how big SecondRound may be in memory so we will
    /// heap allocate and try keep this to a minimum
    second_rounds: Vec<MaybeUninit<Arc<SecondRound>>>,
}

impl<FirstRound, SecondRound, const N: usize> Default
    for Musig2SessionManager<FirstRound, SecondRound, N>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
{
    fn default() -> Self {
        Self {
            tracker: DoubleBoolArray::default(),
            first_rounds: Vec::new(),
            second_rounds: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct OutOfRange;

#[derive(Debug)]
pub struct NotInCorrectRound {
    wanted: SlotState,
    got: SlotState,
}

#[derive(Debug)]
pub struct OtherReferencesActive;

impl<FirstRound, SecondRound, const N: usize> Musig2SessionManager<FirstRound, SecondRound, N>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
{
    pub fn new_session(&mut self, first_round: FirstRound) -> Option<usize> {
        let next_empty = self.tracker.find_next_empty_slot()?;
        if next_empty <= self.first_rounds.len() {
            // we're replacing an existing session
            self.first_rounds[next_empty] = MaybeUninit::new(first_round.into());
        } else {
            // we're not replacing any existing session, so we need to grow
            self.first_rounds.push(MaybeUninit::new(first_round.into()));
        }
        return Some(next_empty);
    }

    #[inline]
    fn slot_state(&self, session_id: usize) -> Result<SlotState, OutOfRange> {
        match session_id < DoubleBoolArray::<N, SlotState>::capacity() {
            true => Ok(self.tracker.get(session_id)),
            false => Err(OutOfRange),
        }
    }

    pub async fn transition_first_to_second_round(
        &mut self,
        session_id: usize,
        hash: [u8; 32],
    ) -> Result<
        (),
        OneOf<(
            NotInCorrectRound,
            OutOfRange,
            OtherReferencesActive,
            RoundFinalizeError,
        )>,
    > {
        match self.slot_state(session_id).map_err(OneOf::new)? {
            SlotState::FirstRound => {
                let arc = unsafe {
                    std::mem::replace(
                        self.first_rounds.get_unchecked_mut(session_id),
                        MaybeUninit::uninit(),
                    )
                    .assume_init()
                };
                let first_round = match Arc::try_unwrap(arc) {
                    Ok(fr) => fr,
                    Err(arc) => {
                        self.first_rounds[session_id] = MaybeUninit::new(arc);
                        return Err(OneOf::new(OtherReferencesActive));
                    }
                };
                let second_round = first_round.finalize(hash).await.map_err(OneOf::new)?;
                self.second_rounds[session_id] = MaybeUninit::new(second_round.into());
                self.tracker.set(session_id, SlotState::SecondRound);
                Ok(())
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: SlotState::FirstRound,
                got: slot_state,
            })),
        }
    }

    pub async fn finalize_second_round(
        &mut self,
        session_id: usize,
    ) -> Result<
        LiftedSignature,
        OneOf<(
            OutOfRange,
            NotInCorrectRound,
            OtherReferencesActive,
            RoundFinalizeError,
        )>,
    > {
        match self.slot_state(session_id).map_err(OneOf::new)? {
            SlotState::SecondRound => {
                let arc = unsafe {
                    std::mem::replace(
                        self.second_rounds.get_unchecked_mut(session_id),
                        MaybeUninit::uninit(),
                    )
                    .assume_init()
                };
                let second_round = match Arc::try_unwrap(arc) {
                    Ok(sr) => sr,
                    Err(arc) => {
                        self.second_rounds[session_id] = MaybeUninit::new(arc);
                        return Err(OneOf::new(OtherReferencesActive));
                    }
                };
                self.tracker.set(session_id, SlotState::Empty);
                Ok(second_round.finalize().await.map_err(OneOf::new)?)
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: SlotState::SecondRound,
                got: slot_state,
            })),
        }
    }

    pub fn first_round(&self, session_id: usize) -> Result<Option<Arc<FirstRound>>, OutOfRange> {
        match self.slot_state(session_id)? {
            SlotState::FirstRound => {
                let first_round = unsafe { self.first_rounds[session_id].assume_init_ref() };
                Ok(Some(first_round.clone()))
            }
            _ => Ok(None),
        }
    }

    pub fn second_round(&self, session_id: usize) -> Result<Option<Arc<SecondRound>>, OutOfRange> {
        match self.slot_state(session_id)? {
            SlotState::SecondRound => {
                let second_round = unsafe { self.second_rounds[session_id].assume_init_ref() };
                Ok(Some(second_round.clone()))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug)]
enum SlotState {
    Empty,
    FirstRound,
    SecondRound,
}

impl TryFrom<(bool, bool)> for SlotState {
    type Error = ();

    fn try_from((a, b): (bool, bool)) -> Result<Self, Self::Error> {
        match (a, b) {
            (false, false) => Ok(Self::Empty),
            (true, false) => Ok(Self::FirstRound),
            (false, true) => Ok(Self::SecondRound),
            _ => Err(()),
        }
    }
}

impl From<SlotState> for (bool, bool) {
    fn from(state: SlotState) -> Self {
        match state {
            SlotState::Empty => (false, false),
            SlotState::FirstRound => (true, false),
            SlotState::SecondRound => (false, true),
        }
    }
}
