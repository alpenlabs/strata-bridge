//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::fmt::Display;

use bitcoin::OutPoint;
use strata_bridge_primitives::{operator_table::OperatorTable, types::DepositIdx};

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
    },
    signals::DepositSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The static configuration for a Deposit State Machine.
///
/// These configurations are set at the creation of the Deposit State Machine and do not change
/// during any state transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositCfg {
    /// The index of the deposit being tracked in a Deposit State Machine.
    deposit_idx: DepositIdx,
    /// The outpoint of the deposit being tracked in a Deposit State Machine.
    deposit_outpoint: OutPoint,
    /// The operators involved in the signing of this deposit.
    operator_table: OperatorTable,
}

/// The state of a Deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositState {
    /// TODO: (@MdTeach)
    Created,
    /// TODO: (@MdTeach)
    GraphGenerated,
    /// TODO: (@MdTeach)
    DepositNoncesCollected,
    /// TODO: (@MdTeach)
    DepositPartialsCollected,
    /// TODO: (@mukeshdroid)
    Deposited,
    /// TODO: (@mukeshdroid)
    Assigned,
    /// TODO: (@mukeshdroid)
    Fulfilled,
    /// TODO: (@mukeshdroid)
    PayoutNoncesCollected,
    /// TODO: (@mukeshdroid)
    PayoutPartialsCollected,
    /// TODO: (@Rajil1213)
    CooperativePathFailed,
    /// TODO: (@Rajil1213)
    Spent,
    /// TODO: (@Rajil1213)
    Aborted,
}

impl Display for DepositState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_str = match self {
            DepositState::Created => "Created",
            DepositState::GraphGenerated => "GraphGenerated",
            DepositState::DepositNoncesCollected => "DepositNoncesCollected",
            DepositState::DepositPartialsCollected => "DepositPartialsCollected",
            DepositState::Deposited => "Deposited",
            DepositState::Assigned => "Assigned",
            DepositState::Fulfilled => "Fulfilled",
            DepositState::PayoutNoncesCollected => "PayoutNoncesColletced",
            DepositState::PayoutPartialsCollected => "PayoutPartialsCollected",
            DepositState::CooperativePathFailed => "CooperativePathFailed",
            DepositState::Spent => "Spent",
            DepositState::Aborted => "Aborted",
        };
        write!(f, "{}", state_str)
    }
}

impl Default for DepositState {
    fn default() -> Self {
        // TODO: (@MdTeach) Remove this impl once `new` starts taking arguments.
        DepositState::new()
    }
}

impl DepositState {
    /// Creates a new Deposit State in the `Created` state.
    pub const fn new() -> Self {
        DepositState::Created
    }
}

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositSM {
    /// The static configuration for this Deposit State Machine.
    cfg: DepositCfg,
    /// The current state of the Deposit State Machine.
    state: DepositState,
}

impl StateMachine for DepositSM {
    type Duty = DepositDuty;
    type OutgoingSignal = DepositSignal;
    type Event = DepositEvent;
    type Error = DSMError;

    fn process_event(
        &mut self,
        event: Self::Event,
    ) -> Result<SMOutput<Self::Duty, Self::OutgoingSignal>, Self::Error> {
        match event {
            DepositEvent::DepositRequest => self.process_deposit_request(),
            DepositEvent::GraphMessage(_graph_msg) => self.process_graph_available(),
            DepositEvent::NonceReceived => self.process_nonce_received(),
            DepositEvent::PartialReceived => self.process_partial_received(),
            DepositEvent::DepositConfirmed => self.process_deposit_confirmed(),
            DepositEvent::Assignment => self.process_assignment(),
            DepositEvent::FulfillmentConfirmed => self.process_fulfillment(),
            DepositEvent::PayoutNonceReceived => self.process_payout_nonce_received(),
            DepositEvent::PayoutPartialReceived => self.process_payout_partial_received(),
            DepositEvent::PayoutConfirmed => self.process_payout_confirmed(),
            DepositEvent::NewBlock => self.process_new_block(),
        }
    }
}

/// The output of the Deposit State Machine after processing an event.
///
/// This is a type alias for [`SMOutput`] specialized to the Deposit State Machine's
/// duty and signal types. This ensures that the Deposit SM can only emit [`DepositDuty`]
/// duties and [`DepositSignal`] signals.
pub type DSMOutput = SMOutput<DepositDuty, DepositSignal>;

impl DepositSM {
    /// Creates a new Deposit State Machine with the given configuration.
    pub const fn new(cfg: DepositCfg) -> Self {
        DepositSM {
            cfg,
            state: DepositState::new(),
        }
    }

    /// Returns a reference to the configuration of the Deposit State Machine.
    pub const fn cfg(&self) -> &DepositCfg {
        &self.cfg
    }

    /// Returns a reference to the current state of the Deposit State Machine.
    pub const fn state(&self) -> &DepositState {
        &self.state
    }

    // **DESIGN PRINCIPLE**
    //
    // author: @ProofOfKeags
    //
    // All the state transition functions that handle state machine events have these semantics:
    //
    // If an event cannot be consumed by the SM it should give back an error. If it does get
    // consumed by the SM it should not have the same state prior. Not all errors need to be fatal
    // but semantically there's no difference between rejecting an event because it has the wrong
    // internal state or rejecting an event because the event doesn't apply to the machine. Either
    // way the error semantics should be about whether or not the event was accepted or rejected.
    // We can annotate it with different reasons still if we use errors.

    // NOTE: all of the following functions are placeholders for the actual state transition logic.
    // they each receive the appropriate data required for the state transitions.

    fn process_deposit_request(&self) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        todo!("@MdTeach")
    }

    fn process_graph_available(&mut self) -> DSMResult<DSMOutput> {
        todo!("@MdTeach")
    }

    fn process_nonce_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@MdTeach")
    }

    fn process_partial_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@MdTeach")
    }

    fn process_deposit_confirmed(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
    }

    fn process_assignment(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
    }

    fn process_fulfillment(&self) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        todo!("@mukeshdroid")
    }

    fn process_payout_nonce_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
    }

    fn process_payout_partial_received(&mut self) -> DSMResult<DSMOutput> {
        todo!("@mukeshdroid")
    }

    fn process_payout_confirmed(&mut self) -> DSMResult<DSMOutput> {
        todo!("@Rajil1213")
    }

    fn process_new_block(&mut self) -> DSMResult<DSMOutput> {
        todo!("@Rajil1213")
    }
}
