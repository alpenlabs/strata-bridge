//! This module contains the Musig2SessionManager which manages in-memory MuSig2
//! sessions globally for a given server. This allows ergonomic (and correct) usage
//! of Secret Service's musig2 features.

use std::sync::Arc;

use bitcoin::OutPoint;
use hashbrown::HashMap;
use musig2::{errors::RoundFinalizeError, LiftedSignature};
use secret_service_proto::v1::traits::{Musig2SignerFirstRound, Musig2SignerSecondRound, Server};
use terrors::OneOf;
use tokio::sync::Mutex;

/// [`Musig2SessionManager`] is responsible for tracking and managing Secret Service's
/// MuSig2 sessions.
#[derive(Debug)]
pub struct Musig2SessionManager<R1, R2>
where
    R2: Musig2SignerSecondRound<Server>,
    R1: Musig2SignerFirstRound<Server, R2>,
{
    /// Stores first/second rounds of musig2 instances
    rounds: HashMap<OutPoint, Slot<R1, R2>>,
}

impl<R1, R2> Default for Musig2SessionManager<R1, R2>
where
    R2: Musig2SignerSecondRound<Server>,
    R1: Musig2SignerFirstRound<Server, R2>,
{
    fn default() -> Self {
        Self {
            rounds: HashMap::new(),
        }
    }
}

#[derive(Debug)]
enum Slot<R1, R2> {
    FirstRound(Arc<Mutex<R1>>),
    SecondRound(Arc<Mutex<R2>>),
}

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

impl<R1, R2> Musig2SessionManager<R1, R2>
where
    R2: Musig2SignerSecondRound<Server>,
    R1: Musig2SignerFirstRound<Server, R2>,
{
    /// Requests a new session ID from the session manager for a given first round.
    pub fn new_session(&mut self, op: OutPoint, r1: R1) {
        self.rounds
            .insert(op, Slot::FirstRound(Arc::new(r1.into())));
    }

    /// Attempts to transition a MuSig2 session from the first round by
    /// finalizing it.
    pub async fn transition_first_to_second_round(
        &mut self,
        outpoint: OutPoint,
        hash: [u8; 32],
    ) -> Result<(), OneOf<(NotInCorrectRound, OtherReferencesActive, RoundFinalizeError)>> {
        let arc = match self.rounds.remove(&outpoint) {
            Some(Slot::FirstRound(arc)) => arc,
            Some(Slot::SecondRound(arc)) => {
                self.rounds.insert(outpoint, Slot::SecondRound(arc));
                return Err(OneOf::new(NotInCorrectRound {
                    wanted: SlotState::FirstRound,
                    got: SlotState::SecondRound,
                }));
            }
            None => {
                return Err(OneOf::new(NotInCorrectRound {
                    wanted: SlotState::FirstRound,
                    got: SlotState::Empty,
                }))
            }
        };

        // attempt to unwrap the arc so we can consume it during finalisation
        let r1 = match Arc::try_unwrap(arc) {
            Ok(fr) => fr.into_inner(),
            Err(arc) => {
                self.rounds.insert(outpoint, Slot::FirstRound(arc));
                return Err(OneOf::new(OtherReferencesActive));
            }
        };
        let r2 = r1.finalize(hash).await.map_err(OneOf::new)?;
        self.rounds
            .insert(outpoint, Slot::SecondRound(Arc::new(r2.into())));
        Ok(())
    }

    /// Attempts to finalize the second round of a MuSig2 session.
    pub async fn finalize_second_round(
        &mut self,
        outpoint: OutPoint,
    ) -> Result<
        LiftedSignature,
        OneOf<(NotInCorrectRound, OtherReferencesActive, RoundFinalizeError)>,
    > {
        let arc = match self.rounds.remove(&outpoint) {
            Some(Slot::SecondRound(arc)) => arc,
            Some(Slot::FirstRound(arc)) => {
                self.rounds.insert(outpoint, Slot::FirstRound(arc));
                return Err(OneOf::new(NotInCorrectRound {
                    wanted: SlotState::SecondRound,
                    got: SlotState::FirstRound,
                }));
            }
            None => {
                return Err(OneOf::new(NotInCorrectRound {
                    wanted: SlotState::FirstRound,
                    got: SlotState::Empty,
                }))
            }
        };

        // attempt to unwrap the arc so we can consume it during finalisation
        let r2 = match Arc::try_unwrap(arc) {
            Ok(fr) => fr.into_inner(),
            Err(arc) => {
                self.rounds.insert(outpoint, Slot::SecondRound(arc));
                return Err(OneOf::new(OtherReferencesActive));
            }
        };
        let sig = r2.finalize().await.map_err(OneOf::new)?;
        Ok(sig)
    }

    /// Attempts to retrieve the first round of a MuSig2 session.
    pub fn first_round(&self, outpoint: &OutPoint) -> Option<Arc<Mutex<R1>>> {
        match self.rounds.get(outpoint) {
            Some(Slot::FirstRound(r1)) => Some(r1.clone()),
            _ => None,
        }
    }

    /// Attempts to retrieve the second round of a MuSig2 session.
    pub fn second_round(&self, outpoint: &OutPoint) -> Option<Arc<Mutex<R2>>> {
        match self.rounds.get(outpoint) {
            Some(Slot::SecondRound(r2)) => Some(r2.clone()),
            _ => None,
        }
    }
}

/// Represents the state of a slot in the MuSig2 session manager.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SlotState {
    /// There's no MuSig2 session in this slot.
    Empty,

    /// There's a MuSig2 session in this slot in its first round stage.
    FirstRound,

    /// There's a MuSig2 session in this slot in its second round stage.
    SecondRound,
}
