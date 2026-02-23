//! The Deposit State Machine (DSM).
//!
//! Responsible for driving deposit progress by reacting to events and
//! producing the required duties and signals.

use std::sync::Arc;

use bitcoin::{OutPoint, XOnlyPublicKey, relative};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors2::{n_of_n::NOfNConnector, prelude::DepositRequestConnector};
use strata_bridge_primitives::{operator_table::OperatorTable, types::BitcoinBlockHeight};
use strata_bridge_tx_graph2::transactions::prelude::{DepositData, DepositTx};

use crate::{
    deposit::{
        config::DepositSMCfg,
        context::DepositSMCtx,
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
        state::DepositState,
    },
    signals::DepositSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositSM {
    /// Context associated with this Deposit State Machine instance.
    pub context: DepositSMCtx,
    /// The current state of the Deposit State Machine.
    pub state: DepositState,
}

impl StateMachine for DepositSM {
    type Config = Arc<DepositSMCfg>;
    type Duty = DepositDuty;
    type OutgoingSignal = DepositSignal;
    type Event = DepositEvent;
    type Error = DSMError;

    fn process_event(
        &mut self,
        cfg: Self::Config,
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
            DepositEvent::WithdrawalAssigned(assignment) => {
                self.process_assignment(cfg, assignment)
            }
            DepositEvent::FulfillmentConfirmed(fulfillment) => {
                self.process_fulfillment(cfg, fulfillment)
            }
            DepositEvent::PayoutDescriptorReceived(descriptor) => {
                self.process_payout_descriptor_received(cfg, descriptor)
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
        bridge_cfg: Arc<DepositSMCfg>,
        operator_table: OperatorTable,
        deposit_data: DepositData,
        depositor_pubkey: XOnlyPublicKey,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        let network = bridge_cfg.network();
        let deposit_amount = bridge_cfg.deposit_amount();
        let deposit_time_lock = relative::LockTime::from_height(bridge_cfg.recovery_delay);
        let n_of_n_pubkey = operator_table.aggregated_btc_key().x_only_public_key().0;

        let deposit_request_connetor = DepositRequestConnector::new(
            bridge_cfg.network,
            n_of_n_pubkey,
            depositor_pubkey,
            deposit_time_lock,
            deposit_amount,
        );
        let non_connector = NOfNConnector::new(network, n_of_n_pubkey, deposit_amount);

        let deposit_idx = deposit_data.deposit_idx;
        let deposit_tx = DepositTx::new(deposit_data, non_connector, deposit_request_connetor);

        let deposit_outpoint = OutPoint::new(deposit_tx.as_ref().compute_txid(), 0); // always the first output (for now)
        let context = DepositSMCtx {
            deposit_idx,
            deposit_outpoint,
            operator_table,
        };

        DepositSM {
            context,
            state: DepositState::new(deposit_tx, block_height),
        }
    }

    /// Returns a reference to the Deposit State Machine params.
    pub const fn context(&self) -> &DepositSMCtx {
        &self.context
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
    pub(super) fn check_operator_idx<E>(&self, operator_idx: u32, inner_event: &E) -> DSMResult<()>
    where
        E: Clone + Into<DepositEvent>,
    {
        if self.context().operator_table().contains_idx(&operator_idx) {
            Ok(())
        } else {
            Err(DSMError::rejected(
                self.state().clone(),
                inner_event.clone().into(),
                format!("Operator index {} not in operator table", operator_idx),
            ))
        }
    }
}
