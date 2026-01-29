//! The Deposit State Machine (DSM).
//!
//! Responsible for driving deposit progress by reacting to events and
//! producing the required duties and signals.
use bitcoin::{Amount, Network, XOnlyPublicKey, relative::LockTime};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph2::transactions::prelude::DepositData;

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::DSMError,
        events::DepositEvent,
        state::{DepositState, config::DepositCfg},
    },
    signals::DepositSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The number of blocks after the fulfillment confirmation after which the cooperative payout path
/// is considered to have failed.
// TODO: (@Rajil1213) Move this to a config
pub const COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS: u64 = 144; // Approx. 24 hours

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSM {
    /// The static configuration for this Deposit State Machine.
    pub cfg: DepositCfg,
    /// The current state of the Deposit State Machine.
    pub state: DepositState,
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
            DepositEvent::UserTakeBack { tx } => self.process_drt_takeback(tx),
            DepositEvent::GraphMessage(graph_msg) => self.process_graph_available(graph_msg),
            DepositEvent::NonceReceived {
                nonce,
                operator_idx,
            } => self.process_nonce_received(nonce, operator_idx),
            DepositEvent::PartialReceived {
                partial_sig,
                operator_idx,
            } => self.process_partial_received(partial_sig, operator_idx),
            DepositEvent::DepositConfirmed {
                deposit_transaction,
            } => self.process_deposit_confirmed(event_description, deposit_transaction),
            DepositEvent::WithdrawalAssigned {
                assignee,
                deadline,
                recipient_desc,
            } => self.process_assignment(event_description, assignee, deadline, recipient_desc),
            DepositEvent::FulfillmentConfirmed {
                fulfillment_transaction,
                fulfillment_height,
            } => self.process_fulfillment(
                event_description,
                fulfillment_transaction,
                fulfillment_height,
                COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
            ),
            DepositEvent::PayoutDescriptorReceived { operator_desc } => {
                self.process_payout_descriptor_received(event_description, operator_desc)
            }
            DepositEvent::PayoutNonceReceived {
                payout_nonce,
                operator_idx,
            } => self.process_payout_nonce_received(event_description, payout_nonce, operator_idx),
            DepositEvent::PayoutPartialReceived {
                partial_signature,
                operator_idx,
            } => self.process_payout_partial_received(
                event_description,
                partial_signature,
                operator_idx,
            ),
            DepositEvent::PayoutConfirmed { tx } => self.process_payout_confirmed(&tx),
            DepositEvent::NewBlock { block_height } => self.process_new_block(block_height),
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
    /// Creates a new [`DepositSM`] using the provided configuration and deposit data.
    ///
    /// The state machine starts in [`DepositState::Created`] by constructing an initial
    /// [`DepositState`] via [`DepositState::new`].
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        cfg: DepositCfg,
        deposit_ammount: Amount,
        deposit_time_lock: LockTime,
        network: Network,
        deposit_data: DepositData,
        depositor_pubkey: XOnlyPublicKey,
        n_of_n_pubkey: XOnlyPublicKey,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositSM {
            cfg,
            state: DepositState::new(
                deposit_ammount,
                deposit_time_lock,
                network,
                deposit_data,
                depositor_pubkey,
                n_of_n_pubkey,
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

    /// Returns a mutable reference to the current state of the Deposit State Machine.
    pub const fn state_mut(&mut self) -> &mut DepositState {
        &mut self.state
    }

    /// Returns `true` if the operator index exists in the operator table.
    pub fn validate_operator_idx(&self, operator_idx: OperatorIdx) -> bool {
        self.cfg()
            .operator_table
            .idx_to_btc_key(&operator_idx)
            .is_some()
    }
}
