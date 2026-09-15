//! State-machine events and covenant initialization intent.

use std::{
    convert::Infallible,
    fmt::{Display, Formatter, Result as FmtResult},
};

use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    covenant::{CovenantId, StakeKey},
    operator_set_schedule::OperatorSetSchedule,
    operator_table::PublicOperatorTable,
    types::BitcoinBlockHeight,
};

use super::{ConfirmedExit, MembershipUpdate, OperatorSetError, OperatorSetSM};
use crate::{
    signals::Signal,
    state_machine::{SMOutput, StateMachine},
};

/// Inputs to the public membership state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorSetEvent {
    /// Finalizes a consecutive block using its ordered, validated exits.
    NewBlock {
        /// The Bitcoin height being finalized.
        block_height: BitcoinBlockHeight,
        /// Classified exits in Bitcoin transaction order.
        exits: Vec<ConfirmedExit>,
    },
    /// Installs authorized registrations and the remaining admin schedule.
    UpdateOperatorTable {
        /// Complete historical and future registrations.
        registrations: OperatorSetSchedule,
        /// Remaining authorized operations; equal-height operations retain their supplied order.
        pending_updates: Vec<MembershipUpdate>,
    },
}

impl Display for OperatorSetEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::NewBlock { block_height, .. } => write!(f, "NewBlock at height {block_height}"),
            Self::UpdateOperatorTable { .. } => write!(f, "UpdateOperatorTable"),
        }
    }
}

/// Stake initialization requests for exact covenant membership.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatorSetSignal {
    /// Requests a stake for one member of the specified covenant.
    ///
    /// Repeated requests identify the same stake and must preserve its existing progress.
    InitializeStake {
        /// The covenant and permanent owner index requested by the membership state machine.
        stake_key: StakeKey,
        /// The immutable public membership of that covenant, without a local signing role.
        operator_table: PublicOperatorTable,
    },
}

impl From<OperatorSetSignal> for Signal {
    fn from(signal: OperatorSetSignal) -> Self {
        Self::FromOperatorSet(signal)
    }
}

/// Membership emits local initialization signals and has no external duties.
pub type OperatorSetOutput = SMOutput<Infallible, OperatorSetSignal>;

impl StateMachine for OperatorSetSM {
    type Config = ();
    type Duty = Infallible;
    type Event = OperatorSetEvent;
    type OutgoingSignal = OperatorSetSignal;
    type Error = OperatorSetError;

    fn process_event(
        &mut self,
        (): (),
        event: OperatorSetEvent,
    ) -> Result<OperatorSetOutput, OperatorSetError> {
        match event {
            OperatorSetEvent::NewBlock {
                block_height,
                exits,
            } => {
                let changed = self.apply_block(block_height, &exits)?;
                let signals = if changed {
                    self.initialization_signals()?
                } else {
                    vec![]
                };
                Ok(SMOutput::with_signals(signals))
            }
            OperatorSetEvent::UpdateOperatorTable {
                registrations,
                pending_updates,
            } => {
                let changed = self.update_operator_table(registrations, pending_updates)?;
                let output = SMOutput::new();
                Ok(if changed {
                    output
                } else {
                    output.mark_unchanged()
                })
            }
        }
    }
}

impl OperatorSetSM {
    /// Derives initialization intent for all current members, including surviving operators.
    ///
    /// The requests depend only on the current covenant and its public operator table.
    /// Repeated calls leave the state unchanged and produce identical stake identities.
    pub fn initialization_signals(&self) -> Result<Vec<OperatorSetSignal>, OperatorSetError> {
        Ok(initialization_signals(
            self.current_covenant,
            self.current_operator_table()?,
        ))
    }

    /// Projects ordered admin operations through a future activation and requests its stakes.
    ///
    /// Exited indices remain excluded. This changes neither membership nor processing clocks;
    /// repeating the request produces the same identities for idempotent initialization.
    pub fn prepare_covenant(
        &self,
        activation_height: BitcoinBlockHeight,
    ) -> Result<OperatorSetOutput, OperatorSetError> {
        if activation_height <= self.last_block_height {
            return Err(OperatorSetError::InvalidPreparationHeight(
                activation_height,
            ));
        }
        let mut projected = self.clone();
        let mut changed_at_target = false;
        for update in self.pending_updates.due(activation_height) {
            let effective = projected.apply_update(update.clone())?;
            changed_at_target |= effective && update.activation_height == activation_height;
        }
        if !changed_at_target {
            return Ok(SMOutput::new().mark_unchanged());
        }
        let table = projected.current_operator_table()?;
        let covenant = CovenantId::from_operator_table(&table, activation_height)
            .map_err(|_| OperatorSetError::InvalidMembership)?;
        Ok(SMOutput::with_signals(initialization_signals(covenant, table)).mark_unchanged())
    }
}

fn initialization_signals(
    covenant: CovenantId,
    table: PublicOperatorTable,
) -> Vec<OperatorSetSignal> {
    table
        .operator_idxs()
        .into_iter()
        .map(|operator| OperatorSetSignal::InitializeStake {
            stake_key: StakeKey { covenant, operator },
            operator_table: table.clone(),
        })
        .collect()
}
