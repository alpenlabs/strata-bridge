//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::fmt::Display;

use crate::{
    deposit::{duties::DepositDuty, errors::DSMResult, events::DepositEvent},
    signals::Signal,
};

/// The output of the Deposit State Machine after processing an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DSMOutput {
    /// The duties that need to be performed.
    pub duties: Vec<DepositDuty>,
    /// The messages that need to be sent to other state machines.
    pub messages: Vec<Signal>,
}

/// The state machine for the Deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositSM {
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

impl Display for DepositSM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_str = match self {
            DepositSM::Created => "Created",
            DepositSM::GraphGenerated => "GraphGenerated",
            DepositSM::DepositNoncesCollected => "DepositNoncesCollected",
            DepositSM::DepositPartialsCollected => "DepositPartialsCollected",
            DepositSM::Deposited => "Deposited",
            DepositSM::Assigned => "Assigned",
            DepositSM::Fulfilled => "Fulfilled",
            DepositSM::PayoutNoncesCollected => "PayoutNoncesColletced",
            DepositSM::PayoutPartialsCollected => "PayoutPartialsCollected",
            DepositSM::CooperativePathFailed => "CooperativePathFailed",
            DepositSM::Spent => "Spent",
            DepositSM::Aborted => "Aborted",
        };
        write!(f, "{}", state_str)
    }
}

impl Default for DepositSM {
    fn default() -> Self {
        // TODO: (@MdTeach) Remove this impl once `new` starts taking arguments.
        DepositSM::new()
    }
}

impl DepositSM {
    /// Creates a new [`DepositSM`] in the `Created` state.
    pub const fn new() -> Self {
        DepositSM::Created
    }

    /// Receives an event and performs the appropriate state transitions.
    pub fn process_event(&mut self, event: DepositEvent) -> DSMResult<DSMOutput> {
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
