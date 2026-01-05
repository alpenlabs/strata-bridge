//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::fmt::Display;

use bitcoin::{Block, OutPoint, Transaction};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{DepositIdx, OperatorIdx},
};

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
    },
    signals::DepositSignal,
    state_machine::{SMOutput, StateMachine},
};

// TODO: (@Rajil1213) Maybe move configuration to a separate `config` module.
// This module will have a
// - `DepositSMCfg` which contains values that are static over the
//  lifetime of a single Deposit State Machine, and a
// - `DepositGlobalCfg` which contains values that are static over the lifetime of all Deposit State
//   Machines
//  (such as timelocks).

/// The static configuration for a Deposit State Machine.
///
/// These configurations are set at the creation of the Deposit State Machine and do not change
/// during any state transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositCfg {
    /// The index of the deposit being tracked in a Deposit State Machine.
    pub(super) deposit_idx: DepositIdx,
    /// The outpoint of the deposit being tracked in a Deposit State Machine.
    pub(super) deposit_outpoint: OutPoint,
    /// The operators involved in the signing of this deposit.
    pub(super) operator_table: OperatorTable,
}

/// The state of a Deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositState {
    /// TODO: (@MdTeach)
    Created {
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@MdTeach)
    GraphGenerated {
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@MdTeach)
    DepositNoncesCollected {
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@MdTeach)
    DepositPartialsCollected {
        /// The outpoint of the deposit request that is to be spent by the Deposit Transaction.
        deposit_request_outpoint: OutPoint,
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@mukeshdroid)
    Deposited {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@mukeshdroid)
    Assigned {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// TODO: (@mukeshdroid)
    Fulfilled {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
        /// The index of the operator assigned to the deposit.
        assignee: OperatorIdx,
    },
    /// TODO: (@mukeshdroid)
    PayoutNoncesCollected {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
        /// The index of the operator assigned to the deposit.
        assignee: OperatorIdx,
    },
    /// TODO: (@mukeshdroid)
    PayoutPartialsCollected {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// This state represents the scenario where the cooperative payout path has failed,
    ///
    /// This happens if the assignee was not able to collect the requisite nonces/partials for
    /// the cooperative payout transaction.
    CooperativePathFailed {
        /// The height of the latest block that this state machine is aware of.
        block_height: u64,
    },
    /// This represents the terminal state where the deposit has been spent.
    Spent,
    /// TODO: (@Rajil1213)
    Aborted,
}

impl Display for DepositState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state_str = match self {
            DepositState::Created { .. } => "Created",
            DepositState::GraphGenerated { .. } => "GraphGenerated",
            DepositState::DepositNoncesCollected { .. } => "DepositNoncesCollected",
            DepositState::DepositPartialsCollected { .. } => "DepositPartialsCollected",
            DepositState::Deposited { .. } => "Deposited",
            DepositState::Assigned { .. } => "Assigned",
            DepositState::Fulfilled { .. } => "Fulfilled",
            DepositState::PayoutNoncesCollected { .. } => "PayoutNoncesColletced",
            DepositState::PayoutPartialsCollected { .. } => "PayoutPartialsCollected",
            DepositState::CooperativePathFailed { .. } => "CooperativePathFailed",
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
    pub fn new() -> Self {
        DepositState::Created {
            deposit_request_outpoint: OutPoint::default(),
            block_height: 0,
        }
    }

    // TODO: (@Rajil1213, @MdTeach, @mukeshdroid) Add introspection methods here
}

// TODO: (@Rajil1213) Move `DepositSM` to a separate `state-machine` module once complete (to avoid
// merge conflicts now).

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositSM {
    /// The static configuration for this Deposit State Machine.
    pub(super) cfg: DepositCfg,
    /// The current state of the Deposit State Machine.
    pub(super) state: DepositState,
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
            DepositEvent::UserTakeBack { tx } => self.process_drt_takeback(tx),
            DepositEvent::GraphMessage(_graph_msg) => self.process_graph_available(),
            DepositEvent::NonceReceived => self.process_nonce_received(),
            DepositEvent::PartialReceived => self.process_partial_received(),
            DepositEvent::DepositConfirmed => self.process_deposit_confirmed(),
            DepositEvent::Assignment => self.process_assignment(),
            DepositEvent::FulfillmentConfirmed => self.process_fulfillment(),
            DepositEvent::PayoutNonceReceived => self.process_payout_nonce_received(),
            DepositEvent::PayoutPartialReceived => self.process_payout_partial_received(),
            DepositEvent::PayoutConfirmed { tx } => self.process_payout_confirmed(&tx),
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
    pub fn new(cfg: DepositCfg) -> Self {
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

    /// Returns a mutable reference to the current state of the Deposit State Machine.
    pub const fn state_mut(&mut self) -> &mut DepositState {
        &mut self.state
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

    /// Processes the event where the user takes back the deposit request output.
    ///
    /// This can happen if any of the operators are not operational for the entire duration of the
    /// take back period.
    fn process_drt_takeback(
        &mut self,
        tx: Transaction,
    ) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        match self.state() {
            DepositState::Created {
                deposit_request_outpoint,
                ..
            }
            | DepositState::GraphGenerated {
                deposit_request_outpoint,
                ..
            }
            | DepositState::DepositNoncesCollected {
                deposit_request_outpoint,
                ..
            }
            | DepositState::DepositPartialsCollected {
                deposit_request_outpoint,
                ..
            } => {
                if tx
                    .input
                    .iter()
                    .find(|input| input.previous_output == *deposit_request_outpoint)
                    .is_some_and(|input| input.witness.len() > 1)
                // HACK: (@Rajil1213) take back path is a script-spend and so has multiple witness
                // elements, as opposed to the Deposit Transaction which is a key-spend and has only
                // one witness element (the schnorr signature). The proper way to check this is to
                // see if the witness contains the takeback script as the script
                // being used. But a length-check is both simpler and sufficient.
                {
                    // Transition to Aborted state
                    self.state = DepositState::Aborted;

                    // This is a terminal state
                    Ok(SMOutput {
                        duties: vec![],
                        signals: vec![],
                    })
                } else {
                    Err(DSMError::Rejected {
                        state: self.state().clone(),
                        reason: format!(
                            "Transaction {} is not a take back transaction for the deposit request outpoint {}",
                            tx.compute_txid(),
                            deposit_request_outpoint
                        ),
                    })
                }
            }
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::UserTakeBack { tx }.to_string(),
                state: self.state.to_string(),
                reason: None,
            }),
        }
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

    /// Processes the confirmation of a transaction that spends the deposit outpoint being tracked
    /// by this state machine.
    ///
    /// This outpoint can be spent via the following transactions:
    ///
    /// - A sweep transaction in the event of a hard upgrade (migration) of deposited UTXOs
    /// - A cooperative payout transaction, if the cooperative path was successful.
    /// - An uncontested payout transaction, if the assignee published a claim that went
    ///   uncontested.
    /// - A contested payout transaction, if the assignee published a claim that was contested but
    ///   not successfully.
    fn process_payout_confirmed(&mut self, tx: &Transaction) -> DSMResult<DSMOutput> {
        match self.state() {
            // It must be the sweep transaction in case of a hard upgrade
            DepositState::Deposited { .. }
            // It must be the cooperative payout transaction
            | DepositState::PayoutPartialsCollected { .. }
            // It can be a contested/uncontested payout transaction
            // This can also be a coopertive payout transaction due to delayed settlement of the
            // transaction on-chain or because each operator has a different configuration for how
            // long to wait till the cooperative payout path is considered failed.
            | DepositState::CooperativePathFailed { .. }
            // The assignee can withhold their own partial and broadcast the payout tx themselves,
            // In this case, we still want other nodes' state machines to transition properly.
            // This can also happen if there are network delays.
            | DepositState::PayoutNoncesCollected { .. } => {
                tx
                .input
                .iter()
                .any(|input| input.previous_output == self.cfg().deposit_outpoint)
                .ok_or(DSMError::InvalidEvent {
                    state: self.state().to_string(),
                    event: DepositEvent::PayoutConfirmed { tx: tx.clone() }.to_string(),
                    reason: format!(
                        "Transaction {} does not spend from the expected deposit outpoint {}",
                        tx.compute_txid(),
                        self.cfg().deposit_outpoint
                        ).into(),
                })?;

                // Transition to Spent state
                self.state = DepositState::Spent;

                // This is a terminal state
                Ok(SMOutput {
                    duties: vec![],
                    signals: vec![],
                })
            }
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::PayoutConfirmed { tx: tx.clone() }.to_string(),
                state: self.state.to_string(),
                reason: None
            }),
        }
    }

    fn process_new_block(&mut self) -> DSMResult<DSMOutput> {
        todo!("@Rajil1213")
    }
}
