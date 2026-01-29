//! The Deposit State Machine (DSM).
//!
//! Responsible for driving deposit progress by reacting to events and
//! producing the required duties and signals.
use bitcoin::{XOnlyPublicKey, relative::LockTime};
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_bridge_tx_graph2::transactions::prelude::DepositData;

use crate::{
    config::BridgeCfg,
    deposit::{
        config::DepositSMCfg, duties::DepositDuty, errors::DSMError, events::DepositEvent,
        state::DepositState,
    },
    signals::DepositSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
///
/// This includes some static configuration along with the actual state of the deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSM {
    /// Bridge-wide configuration shared across all state machines.
    pub bridge_cfg: BridgeCfg,
    /// Per-instance configuration for this specific deposit state machine.
    pub sm_cfg: DepositSMCfg,
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
        match event {
            DepositEvent::UserTakeBack(takeback) => self.process_drt_takeback(takeback),
            DepositEvent::GraphMessage(graph_msg) => self.process_graph_available(graph_msg),
            DepositEvent::NonceReceived(nonce_event) => self.process_nonce_received(nonce_event),
            DepositEvent::PartialReceived(partial_event) => {
                self.process_partial_received(partial_event)
            }
            DepositEvent::DepositConfirmed(confirmed) => self.process_deposit_confirmed(confirmed),
            DepositEvent::WithdrawalAssigned(assignment) => self.process_assignment(assignment),
            DepositEvent::FulfillmentConfirmed(fulfillment) => self.process_fulfillment(
                fulfillment,
                self.bridge_cfg.cooperative_payout_timeout_blocks,
            ),
            DepositEvent::PayoutDescriptorReceived(descriptor) => {
                self.process_payout_descriptor_received(descriptor)
            }
            DepositEvent::PayoutNonceReceived(payout_nonce) => {
                self.process_payout_nonce_received(payout_nonce)
            }
            DepositEvent::PayoutPartialReceived(payout_partial) => {
                self.process_payout_partial_received(payout_partial)
            }
            DepositEvent::PayoutConfirmed(payout_confirmed) => {
                self.process_payout_confirmed(&payout_confirmed)
            }
            DepositEvent::NewBlock(new_block) => self.process_new_block(new_block),
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
    pub fn new(
        bridge_cfg: BridgeCfg,
        sm_cfg: DepositSMCfg,
        deposit_time_lock: LockTime,
        deposit_data: DepositData,
        depositor_pubkey: XOnlyPublicKey,
        n_of_n_pubkey: XOnlyPublicKey,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        DepositSM {
            bridge_cfg: bridge_cfg.clone(),
            sm_cfg: sm_cfg.clone(),
            state: DepositState::new(
                bridge_cfg.deposit_amount(),
                deposit_time_lock,
                bridge_cfg.network(),
                deposit_data,
                depositor_pubkey,
                n_of_n_pubkey,
                block_height,
            ),
        }
    }

    /// Returns a reference to the per-instance configuration of the Deposit State Machine.
    pub const fn sm_cfg(&self) -> &DepositSMCfg {
        &self.sm_cfg
    }

    /// Returns a reference to the current state of the Deposit State Machine.
    pub const fn state(&self) -> &DepositState {
        &self.state
    }

    /// Returns a mutable reference to the current state of the Deposit State Machine.
    pub const fn state_mut(&mut self) -> &mut DepositState {
        &mut self.state
    }

    /// Checks that the operator index exists, otherwise returns `DSMError::Rejected`.
    pub fn check_operator_idx(
        &self,
        operator_idx: u32,
        event: &impl ToString,
    ) -> Result<(), DSMError> {
        if self
            .sm_cfg
            .operator_table()
            .idx_to_btc_key(&operator_idx)
            .is_some()
        {
            Ok(())
        } else {
            Err(DSMError::Rejected {
                state: self.state().to_string(),
                reason: format!("Operator index {} not in operator table", operator_idx),
                event: event.to_string(),
            })
        }
    }
}
