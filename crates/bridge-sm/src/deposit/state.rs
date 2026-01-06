//! The States for the Deposit State Machine.
//!
//! This module defines the various states that a deposit can be in during its lifecycle
//! with respect to the multisig. Each state represents a specific point in the process
//! of handling a deposit, from the initial request to the final spend.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use bitcoin::{OutPoint, Transaction};
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

// TODO: (@Rajil1213) Maybe move configuration to a separate `config` module.

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositState {
    /// This state represents the initial phase after deposit request confirmation.
    ///
    /// This happens from the confirmation of the deposit request transaction until all operators
    /// have generated and linked their graphs for this deposit.
    Created {
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// The unsigned deposit transaction derived from the deposit request.
        deposit_transaction: Transaction,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO, used for abort handling.
        deposit_request_outpoint: OutPoint,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Operators whose spending graphs have been generated for this deposit.
        linked_graphs: BTreeSet<OperatorIdx>,
    },
    /// This state represents the phase where all operator graphs have been generated.
    ///
    /// This happens from the point where all operator graphs are generated until all public nonces
    /// required to sign the deposit transaction are collected.
    GraphGenerated {
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// The unsigned deposit transaction to be signed.
        deposit_transaction: Transaction,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO.
        deposit_request_outpoint: OutPoint,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Public nonces provided by each operator for signing.
        pubnonces: BTreeMap<OperatorIdx, PubNonce>,
    },
    /// This state represents the phase where all deposit public nonces have been collected.
    ///
    /// This happens from the collection of all deposit public nonces until all partial signatures
    /// have been received.
    DepositNoncesCollected {
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// The deposit transaction being signed.
        deposit_transaction: Transaction,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO.
        deposit_request_outpoint: OutPoint,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Aggregated nonce used to validate partial signatures.
        agg_nonce: AggNonce,

        /// Partial signatures from operators for the deposit transaction.
        partial_signatures: BTreeMap<OperatorIdx, PartialSignature>,
    },
    /// This state represents the phase where all partial signatures have been collected.
    ///
    /// This happens from the collection of all partial signatures until the deposit transaction
    /// is broadcast and confirmed.
    DepositPartialsCollected {
        /// Index identifying this deposit.
        deposit_idx: u32,

        /// Index of the deposit output in the deposit transaction.
        output_index: u32,

        /// Latest Bitcoin block height observed by the state machine.
        block_height: BitcoinBlockHeight,

        /// Block height where the deposit request transaction was confirmed.
        drt_block_height: BitcoinBlockHeight,

        /// Outpoint of the deposit request UTXO.
        deposit_request_outpoint: OutPoint,

        /// The fully signed deposit transaction.
        deposit_transaction: Transaction,

        /// Aggregated signature for the deposit transaction.
        agg_signature: Signature,
    },
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
        let display_str = match self {
            DepositState::Created {
                deposit_idx,
                block_height,
                ..
            } => format!("Created (deposit: {deposit_idx}, height: {block_height})"),
            DepositState::GraphGenerated {
                deposit_idx,
                block_height,
                ..
            } => format!("GraphGenerated (deposit: {deposit_idx}, height: {block_height})"),
            DepositState::DepositNoncesCollected {
                deposit_idx,
                block_height,
                ..
            } => format!("DepositNoncesCollected (deposit: {deposit_idx}, height: {block_height})"),
            DepositState::DepositPartialsCollected {
                deposit_idx,
                block_height,
                ..
            } => {
                format!("DepositPartialsCollected (deposit: {deposit_idx}, height: {block_height})")
            }
            DepositState::Deposited => "Deposited".to_string(),
            DepositState::Assigned => "Assigned".to_string(),
            DepositState::Fulfilled => "Fulfilled".to_string(),
            DepositState::PayoutNoncesCollected => "PayoutNoncesCollected".to_string(),
            DepositState::PayoutPartialsCollected => "PayoutPartialsCollected".to_string(),
            DepositState::CooperativePathFailed => "CooperativePathFailed".to_string(),
            DepositState::Spent => "Spent".to_string(),
            DepositState::Aborted => "Aborted".to_string(),
        };
        write!(f, "{}", display_str)
    }
}

impl DepositState {
    /// Creates a new Deposit State in the `Created` state.
    pub const fn new(
        deposit_idx: u32,
        deposit_transaction: Transaction,
        drt_block_height: BitcoinBlockHeight,
        deposit_request_outpoint: OutPoint,
        output_index: u32,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositState::Created {
            deposit_idx,
            deposit_transaction,
            drt_block_height,
            deposit_request_outpoint,
            output_index,
            block_height,
            linked_graphs: BTreeSet::new(),
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub const fn new(
        cfg: DepositCfg,
        deposit_idx: u32,
        deposit_transaction: Transaction,
        drt_block_height: BitcoinBlockHeight,
        deposit_request_outpoint: OutPoint,
        output_index: u32,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositSM {
            cfg,
            state: DepositState::new(
                deposit_idx,
                deposit_transaction,
                drt_block_height,
                deposit_request_outpoint,
                output_index,
                block_height,
            ),
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
