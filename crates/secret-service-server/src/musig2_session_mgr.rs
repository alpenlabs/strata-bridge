//! This module contains the Musig2SessionManager which manages in-memory MuSig2
//! sessions globally for a given server. This allows ergonomic (and correct) usage
//! of Secret Service's musig2 features.

use std::{mem::MaybeUninit, sync::Arc};

use musig2::{errors::RoundFinalizeError, LiftedSignature};
use secret_service_proto::v1::traits::{Musig2SignerFirstRound, Musig2SignerSecondRound, Server};
use terrors::OneOf;
use tokio::sync::{Mutex, MutexGuard};

use crate::bool_arr::DoubleBoolArray;

/// [`Musig2SessionManager`] is responsible for tracking and managing Secret Service's
/// MuSig2 sessions.
#[derive(Debug)]
pub struct Musig2SessionManager<FirstRound, SecondRound, const N: usize = 128>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    [(); N / 32]:,
{
    /// Tracker is used for tracking whether a session is in first round,
    /// second round or completed.
    ///
    /// Example: when `N=128` means we can track `128 * 32 = 4_096` sessions.
    tracker: DoubleBoolArray<N, SlotState>,

    /// Used to store first rounds of musig2 server instances.
    ///
    /// # Implementation Details
    ///
    /// This is a [`Vec`] because the server doesn't know how big `FirstRound` may be in memory
    /// so it will heap allocate and try keep this to a minimum.
    first_rounds: [MaybeUninit<Arc<Mutex<FirstRound>>>; N],

    /// Used to store second rounds of MuSig2 server instances.
    ///
    /// # Implementation Details
    ///
    /// This is a [`Vec`] because the server doesn't know how big `SecondRound` may be in memory so
    /// it will heap allocate and try keep this to a minimum.
    second_rounds: [MaybeUninit<Arc<Mutex<SecondRound>>>; N],
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
            first_rounds: std::array::from_fn(|_| MaybeUninit::uninit()),
            second_rounds: std::array::from_fn(|_| MaybeUninit::uninit()),
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

/// Permission from the session manager to write to a given slot.
///
/// This allows inspection of the allocated session ID and value before it is transferred
/// to the session manager's ownership.
#[derive(Debug)]
pub struct WritePermission<'a, T> {
    slot: &'a mut MaybeUninit<Arc<Mutex<T>>>,
    session_id: usize,
    t: Arc<Mutex<T>>,
}

impl<T> WritePermission<'_, T> {
    /// Returns a reference to the value inside the Mutex.
    pub async fn value(&self) -> MutexGuard<'_, T> {
        self.t.lock().await
    }

    /// Returns the session ID allocated by the session manager.
    pub fn session_id(&self) -> usize {
        self.session_id
    }
}

impl<T> Drop for WritePermission<'_, T> {
    fn drop(&mut self) {
        self.slot.write(self.t.clone());
    }
}

impl<FirstRound, SecondRound, const N: usize> Musig2SessionManager<FirstRound, SecondRound, N>
where
    SecondRound: Musig2SignerSecondRound<Server>,
    FirstRound: Musig2SignerFirstRound<Server, SecondRound>,
    [(); N / 32]:,
{
    /// Requests a new session ID from the session manager for a given first round.
    pub fn new_session(&mut self, first_round: FirstRound) -> Result<usize, Full> {
        let next_empty = self
            .tracker
            .find_first_slot_with(SlotState::Empty)
            .ok_or(Full)?;
        let slot = self.first_rounds.get_mut(next_empty).unwrap();
        slot.write(Arc::new(first_round.into()));
        self.tracker.set(next_empty, SlotState::FirstRound);
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
                let second_round = first_round
                    .into_inner()
                    .finalize(hash)
                    .await
                    .map_err(OneOf::new)?;
                self.second_rounds[session_id] = MaybeUninit::new(Arc::new(second_round.into()));
                self.tracker.set(session_id, SlotState::SecondRound);
                Ok(())
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: SlotState::FirstRound,
                got: slot_state,
            })),
        }
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
                Ok(second_round
                    .into_inner()
                    .finalize()
                    .await
                    .map_err(OneOf::new)?)
            }
            slot_state => Err(OneOf::new(NotInCorrectRound {
                wanted: SlotState::SecondRound,
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
            SlotState::FirstRound => {
                let first_round = unsafe { self.first_rounds[session_id].assume_init_ref() };
                Ok(Some(first_round.clone()))
            }
            _ => Ok(None),
        }
    }

    /// Attempts to retrieve the second round of a MuSig2 session.
    pub fn second_round(
        &self,
        session_id: usize,
    ) -> Result<Option<Arc<Mutex<SecondRound>>>, OutOfRange> {
        match self.slot_state(session_id)? {
            SlotState::SecondRound => {
                let second_round = unsafe { self.second_rounds[session_id].assume_init_ref() };
                Ok(Some(second_round.clone()))
            }
            _ => Ok(None),
        }
    }
}

/// Represents the state of a slot in the MuSig2 session manager.
///
/// Used with the [`bool_arr`](crate::bool_arr) to improve scan performance.
#[derive(Debug)]
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
