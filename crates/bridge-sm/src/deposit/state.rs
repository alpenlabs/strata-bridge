//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::{collections::BTreeMap, fmt::Display};

use bitcoin::{OutPoint, Transaction, Txid};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::schnorr::Signature};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
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

/// The time lock duration (in blocks) for completing the cooperative payout.
/// TODO:@mukeshdroid This will be later sourced from a config file.
const COOPERATIVE_PAYOUT_TIMELOCK: u64 = 1008;

// TODO: (@Rajil1213) Maybe move configuration to a separate `config` module.

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositState {
    /// TODO: (@MdTeach)
    Created,
    /// TODO: (@MdTeach)
    GraphGenerated,
    /// TODO: (@MdTeach)
    DepositNoncesCollected,
    /// TODO: (@MdTeach)
    DepositPartialsCollected,
    /// This state indicates that the deposit transaction has been confirmed on-chain.
    Deposited {
        /// The last block height observed by this state machine.
        block_height: u32,
    },
    /// This state indicates that a withdrawal has been assigned for this deposit.
    Assigned {
        /// The last block height observed by this state machine.
        block_height: u32,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The block height by which the operator must fulfill the withdrawal.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
    },
    /// This state indicates that the operator has fronted the user.
    Fulfilled {
        /// The last block height observed by this state machine.
        block_height: u32,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The txid of the fulfillment transaction in which the user was fronted.
        fulfillment_txid: Txid,
        /// The block height where the fulfillment transaction was confirmed.
        fulfillment_block_height: BitcoinBlockHeight,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
        /// The operator's descriptor where they want the funds in the cooperative path.
        /// This can only be set once and needs to be provided by the operator.
        operator_desc: Option<Descriptor>,
        /// The pubnonces, indexed by operator, required to sign the cooperative payout
        /// transaction.
        payout_nonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state indicates that all pubnonces required for the cooperative payout has been
    /// collected.
    PayoutNoncesCollected {
        /// The last block height observed by this state machine.
        block_height: u32,
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The txid of the fulfillment transaction in which the user was fronted.
        fulfillment_txid: Txid,
        /// The block height where the fulfillment transaction was confirmed.
        fulfillment_block_height: BitcoinBlockHeight,
        /// The operator's descriptor where they want the funds in the cooperative path.
        payout_output_descriptor: Descriptor,
        /// The block height by which the cooperative payout must be completed.
        cooperative_payment_deadline: BitcoinBlockHeight,
        /// The aggregated nonce for signing the cooperative payout transaction.
        payout_aggregated_nonces: AggNonce,
        /// The partial signatures, indexed by operator, for signing the cooperative payout
        /// transaction.
        payout_partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// This State indicates that all the partial signatures have been collected for cooperative
    /// payout.
    PayoutPartialsCollected {
        /// The last block height observed by this state machine.
        block_height: u32,
        /// The txid of the the cooperative payout transaction.
        payout_txid: Txid,
        /// The aggregated signature for the cooperative payout transaction.
        payout_aggregated_signature: Signature,
    },
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
            DepositState::Deposited { .. } => "Deposited",
            DepositState::Assigned { .. } => "Assigned",
            DepositState::Fulfilled { .. } => "Fulfilled",
            DepositState::PayoutNoncesCollected { .. } => "PayoutNoncesCollected",
            DepositState::PayoutPartialsCollected { .. } => "PayoutPartialsCollected",
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

    // TODO: (@Rajil1213, @MdTeach, @mukeshdroid) Add introspection methods here
}

// TODO: (@Rajil1213) Move `DepositSM` to a separate `state-machine` module once complete (to avoid
// merge conflicts now).

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        let event_description: String = event.to_string();
        match event {
            DepositEvent::DepositRequest => self.process_deposit_request(),
            DepositEvent::GraphMessage(_graph_msg) => self.process_graph_available(),
            DepositEvent::NonceReceived => self.process_nonce_received(),
            DepositEvent::PartialReceived => self.process_partial_received(),
            DepositEvent::DepositConfirmed { .. } => self.process_deposit_confirmed(),
            DepositEvent::Assignment { .. } => self.process_assignment(),
            DepositEvent::FulfillmentConfirmed {
                fulfillment_transaction,
                fulfillment_block_height,
            } => self.process_fulfillment(
                event_description,
                fulfillment_transaction,
                fulfillment_block_height,
                COOPERATIVE_PAYOUT_TIMELOCK,
            ),
            DepositEvent::PayoutNonceReceived { .. } => self.process_payout_nonce_received(),
            DepositEvent::PayoutPartialReceived { .. } => self.process_payout_partial_received(),
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

    fn process_fulfillment(
        &mut self,
        event_description: String,
        fulfillment_transaction: Transaction,
        fulfillment_block_height: BitcoinBlockHeight,
        cooperative_payout_timelock: u64,
    ) -> DSMResult<DSMOutput> {
        match &self.state {
            DepositState::Assigned {
                block_height,
                assignee,
                deadline: _,
                recipient_desc: _,
            } => {
                // Compute the txid of the fulfillemnt Transaction
                let fulfillment_txid: Txid = fulfillment_transaction.compute_txid();

                // Compute the cooperative payout deadline.
                let cooperative_payment_deadline =
                    fulfillment_block_height + cooperative_payout_timelock;

                // Transition to the Fulfilled State
                self.state = DepositState::Fulfilled {
                    block_height: *block_height,
                    assignee: *assignee,
                    fulfillment_txid,
                    fulfillment_block_height,
                    cooperative_payment_deadline,
                    operator_desc: None,
                    payout_nonces: BTreeMap::new(),
                };

                // (TODO: @mukeshdroid) Emit duties and Signals as required. Placeholder for now.

                Ok(DSMOutput::new())
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
            }),
        }
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
