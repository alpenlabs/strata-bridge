//! This module contains the Musig2SessionManager which manages in-memory MuSig2
//! sessions globally for a given server. This allows ergonomic (and correct) usage
//! of Secret Service's musig2 features.

use std::{
    mem::{ManuallyDrop, MaybeUninit},
    ops::Deref,
    sync::Arc,
};

use musig2::{errors::RoundFinalizeError, LiftedSignature};
use secret_service_proto::v1::traits::{Musig2SignerFirstRound, Musig2SignerSecondRound, Server};
use terrors::OneOf;
use tokio::sync::Mutex;

use crate::bool_arr::DoubleBoolArray;

union Round<FirstRound, SecondRound> {
    r1: ManuallyDrop<Arc<Mutex<FirstRound>>>,
    r2: ManuallyDrop<Arc<Mutex<SecondRound>>>,
}

/// [`Musig2SessionManager`] is responsible for tracking and managing Secret Service's
/// MuSig2 sessions.
#[derive(Debug)]
pub struct Musig2SessionManager<FirstRound, SecondRound, const N: usize = 8096>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    [(); N / 32]:,
{
    /// Tracker is used for tracking whether a session is in first round,
    /// second round or completed.
    tracker: DoubleBoolArray<N, SlotState>,

    /// Stores first/second rounds of musig2 instances. self.tracker is used to
    /// determine which round is active.
    rounds: [MaybeUninit<Round<FirstRound, SecondRound>>; N],
}

impl<FirstRound, SecondRound, const N: usize> Default
    for Musig2SessionManager<FirstRound, SecondRound, N>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    [(); N / 32]:,
{
    fn default() -> Self {
        Self {
            tracker: DoubleBoolArray::default(),
            rounds: std::array::from_fn(|_| MaybeUninit::uninit()),
        }
    }
}

/// The provided session index is out of range.
#[derive(Debug)]
pub struct OutOfRange;

/// The session manager is full and cannot accept any more sessions.
#[derive(Debug)]
pub struct Full;

/// The session was assumed to be in a round that it was not in.
#[derive(Debug)]
pub struct NotInCorrectRound {
    /// The state the session was assumed to be in.
    pub wanted: SlotState,

    /// The state the session was actually in.
    pub got: SlotState,
}

/// The server couldn't take ownership of the session because something else was still
/// using it. Try again.
#[derive(Debug)]
pub struct OtherReferencesActive;

impl<FirstRound, SecondRound, const N: usize> Musig2SessionManager<FirstRound, SecondRound, N>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    [(); N / 32]:,
{
    /// Requests a new session ID from the session manager for a given first round.
    pub fn new_session(&mut self, r1: FirstRound) -> Result<usize, Full> {
        let next_empty = self
            .tracker
            .find_first_slot_with(SlotState::Empty)
            .ok_or(Full)?;
        self.put_r1(next_empty, Arc::new(r1.into()))
            .expect("session ID created in next_empty");
        Ok(next_empty)
    }

    #[inline]
    fn slot_state(&self, session_id: usize) -> Result<SlotState, OutOfRange> {
        match session_id < DoubleBoolArray::<N, SlotState>::capacity() {
            true => Ok(self.tracker.get(session_id)),
            false => Err(OutOfRange),
        }
    }

    /// Attempts to transition a MuSig2 session from the first round by
    /// finalizing it.
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
        // take the arc out of the first_rounds array
        let arc = self.take_r1(session_id).map_err(OneOf::broaden)?;
        // attempt to unwrap the arc so we can consume it during finalisation
        let r1 = match Arc::try_unwrap(arc) {
            Ok(fr) => fr.into_inner(),
            Err(r1) => {
                // someone else still has a reference to the first round, so we put
                // the arc back to maintain consistency
                self.put_r1(session_id, r1)
                    .expect("valid session ID and is empty from self.take_r1");
                return Err(OneOf::new(OtherReferencesActive));
            }
        };
        let r2 = r1.finalize(hash).await.map_err(OneOf::new)?;
        self.put_r2(session_id, Arc::new(r2.into()))
            .expect("valid session ID and is empty from self.take_r1");
        Ok(())
    }

    /// Attempts to finalize the second round of a MuSig2 session.
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
        // take the arc of the second round
        let arc = self.take_r2(session_id).map_err(OneOf::broaden)?;
        // try to get r2
        let second_round = match Arc::try_unwrap(arc) {
            Ok(sr) => sr.into_inner(),
            Err(arc) => {
                self.put_r2(session_id, arc)
                    .expect("valid session ID and is empty from self.take_r2");
                return Err(OneOf::new(OtherReferencesActive));
            }
        };
        // attempt to finalize the second round
        Ok(second_round.finalize().await.map_err(OneOf::new)?)
    }

    /// removes a SecondRound from self.second_rounds.
    /// session_id is validated and so is the slot state.
    fn take_r2(
        &mut self,
        session_id: usize,
    ) -> Result<Arc<Mutex<SecondRound>>, OneOf<(NotInCorrectRound, OutOfRange)>> {
        const WANTED_STATE: SlotState = SlotState::SecondRound;
        match self.slot_state(session_id).map_err(OneOf::new)? {
            WANTED_STATE => {
                let arc = unsafe {
                    std::mem::replace(
                        self.rounds.get_unchecked_mut(session_id),
                        MaybeUninit::uninit(),
                    )
                    .assume_init()
                    .r2
                };
                self.tracker.set(session_id, SlotState::Empty);
                Ok(ManuallyDrop::into_inner(arc))
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: WANTED_STATE,
                got: slot_state,
            })),
        }
    }

    /// Puts a SecondRound into an empty slot. Session ID is checked.
    fn put_r2(
        &mut self,
        session_id: usize,
        r2: Arc<Mutex<SecondRound>>,
    ) -> Result<(), OneOf<(NotInCorrectRound, OutOfRange)>> {
        const WANTED_STATE: SlotState = SlotState::Empty;
        match self.slot_state(session_id).map_err(OneOf::new)? {
            WANTED_STATE => {
                self.rounds[session_id] = MaybeUninit::new(Round {
                    r2: ManuallyDrop::new(r2),
                });
                self.tracker.set(session_id, SlotState::SecondRound);
                Ok(())
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: WANTED_STATE,
                got: slot_state,
            })),
        }
    }

    /// removes a FirstRound from self.first_rounds.
    /// session_id is validated and so is the slot state.
    fn take_r1(
        &mut self,
        session_id: usize,
    ) -> Result<Arc<Mutex<FirstRound>>, OneOf<(NotInCorrectRound, OutOfRange)>> {
        const WANTED_STATE: SlotState = SlotState::FirstRound;
        match self.slot_state(session_id).map_err(OneOf::new)? {
            WANTED_STATE => {
                let arc = unsafe {
                    std::mem::replace(
                        self.rounds.get_unchecked_mut(session_id),
                        MaybeUninit::uninit(),
                    )
                    .assume_init()
                    .r1
                };
                self.tracker.set(session_id, SlotState::Empty);
                Ok(ManuallyDrop::into_inner(arc))
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: WANTED_STATE,
                got: slot_state,
            })),
        }
    }

    /// Puts a FirstRound into an empty slot. Session ID is checked.
    fn put_r1(
        &mut self,
        session_id: usize,
        r1: Arc<Mutex<FirstRound>>,
    ) -> Result<(), OneOf<(NotInCorrectRound, OutOfRange)>> {
        const WANTED_STATE: SlotState = SlotState::Empty;
        match self.slot_state(session_id).map_err(OneOf::new)? {
            WANTED_STATE => {
                self.rounds[session_id] = MaybeUninit::new(Round {
                    r1: ManuallyDrop::new(r1),
                });
                self.tracker.set(session_id, SlotState::FirstRound);
                Ok(())
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: WANTED_STATE,
                got: slot_state,
            })),
        }
    }

    /// Attempts to retrieve the first round of a MuSig2 session.
    pub fn first_round(
        &self,
        session_id: usize,
    ) -> Result<Option<Arc<Mutex<FirstRound>>>, OutOfRange> {
        match self.slot_state(session_id)? {
            SlotState::FirstRound => Ok(Some(
                unsafe { &self.rounds[session_id].assume_init_ref().r1 }
                    .deref()
                    .clone(),
            )),
            _ => Ok(None),
        }
    }

    /// Attempts to retrieve the second round of a MuSig2 session.
    pub fn second_round(
        &self,
        session_id: usize,
    ) -> Result<Option<Arc<Mutex<SecondRound>>>, OutOfRange> {
        match self.slot_state(session_id)? {
            SlotState::SecondRound => Ok(Some(
                unsafe { &self.rounds[session_id].assume_init_ref().r2 }
                    .deref()
                    .clone(),
            )),
            _ => Ok(None),
        }
    }
}

/// Represents the state of a slot in the MuSig2 session manager.
///
/// Used with the [`bool_arr`](crate::bool_arr) to improve scan performance.
#[derive(Debug, PartialEq, Eq)]
pub enum SlotState {
    /// There's no MuSig2 session in this slot.
    Empty,

    /// There's a MuSig2 session in this slot in its first round stage.
    FirstRound,

    /// There's a MuSig2 session in this slot in its second round stage.
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
