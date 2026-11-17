//! The Deposit State Machine (DSM).
//!
//! Responsible for driving deposit progress by reacting to events and
//! producing the required duties and signals.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use bitcoin::{Amount, OutPoint, XOnlyPublicKey, relative};
use musig2::PartialSignature;
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::{n_of_n::NOfNConnector, prelude::DepositRequestConnector};
use strata_bridge_primitives::{
    covenant::CovenantId,
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, OperatorIdx},
};
use strata_bridge_tx_graph::transactions::prelude::{DepositData, DepositTx};

use crate::{
    deposit::{
        config::DepositSMCfg,
        context::DepositSMCtx,
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
        state::DepositState,
    },
    error_policy::soften_peer_event_error,
    graph::context::GraphSMCtx,
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
        // A held deposit keeps observing Bitcoin. Peer events are dropped and recovered through
        // nags once this node takes part; accepting them here must not start graph generation
        // or signing.
        if matches!(self.state, DepositState::ParticipationPending { .. }) {
            return match event {
                DepositEvent::NewBlock(block) => self.process_new_block(block),
                DepositEvent::UserTakeBack(takeback) => self.process_drt_takeback(takeback),
                DepositEvent::SafeHarbourAbort(abort) => self.process_safe_harbour_abort(abort),
                DepositEvent::RetryTick(_) | DepositEvent::NagTick(_) => {
                    Ok(DSMOutput::new().mark_unchanged())
                }
                event => Err(DSMError::rejected(
                    self.state.clone(),
                    event,
                    "deposit participation pending",
                )),
            };
        }
        match event {
            DepositEvent::UserTakeBack(takeback) => self.process_drt_takeback(takeback),
            DepositEvent::GraphMessage(graph_msg) => self.process_graph_available(graph_msg),
            DepositEvent::NonceReceived(nonce_event) => {
                let event = DepositEvent::NonceReceived(nonce_event.clone());
                self.process_nonce_received(nonce_event)
                    .map_err(|err| soften_peer_event_error(event, err))
            }
            DepositEvent::PartialReceived(partial_event) => {
                let event = DepositEvent::PartialReceived(partial_event.clone());
                self.process_partial_received(partial_event)
                    .map_err(|err| soften_peer_event_error(event, err))
            }
            DepositEvent::DepositConfirmed(confirmed) => self.process_deposit_confirmed(confirmed),
            DepositEvent::WithdrawalAssigned(assignment) => {
                self.process_assignment(cfg, assignment)
            }
            DepositEvent::FulfillmentConfirmed(fulfillment) => {
                self.process_fulfillment(cfg, fulfillment)
            }
            DepositEvent::PayoutDescriptorReceived(descriptor) => {
                let event = DepositEvent::PayoutDescriptorReceived(descriptor.clone());
                self.process_payout_descriptor_received(cfg, descriptor)
                    .map_err(|err| soften_peer_event_error(event, err))
            }
            DepositEvent::PayoutNonceReceived(payout_nonce) => {
                let event = DepositEvent::PayoutNonceReceived(payout_nonce.clone());
                self.process_payout_nonce_received(payout_nonce)
                    .map_err(|err| soften_peer_event_error(event, err))
            }
            DepositEvent::PayoutPartialReceived(payout_partial) => {
                let event = DepositEvent::PayoutPartialReceived(payout_partial.clone());
                self.process_payout_partial_received(payout_partial)
                    .map_err(|err| soften_peer_event_error(event, err))
            }
            DepositEvent::PayoutConfirmed(payout_confirmed) => {
                self.process_payout_confirmed(&payout_confirmed)
            }
            DepositEvent::SafeHarbourAbort(abort) => self.process_safe_harbour_abort(abort),
            DepositEvent::SweepRequested(sweep_request) => {
                self.process_sweep_request(cfg, sweep_request)
            }
            DepositEvent::SweepNonceReceived(sweep_nonce) => {
                let event = DepositEvent::SweepNonceReceived(sweep_nonce.clone());
                self.process_sweep_nonce_received(sweep_nonce)
                    .map_err(|err| soften_peer_event_error(event, err))
            }
            DepositEvent::SweepPartialReceived(sweep_partial) => {
                let event = DepositEvent::SweepPartialReceived(sweep_partial.clone());
                self.process_sweep_partial_received(sweep_partial)
                    .map_err(|err| soften_peer_event_error(event, err))
            }
            DepositEvent::NewBlock(new_block) => self.process_new_block(new_block),
            DepositEvent::RetryTick(_) => self.process_retry_tick(cfg),
            DepositEvent::NagTick(_) => self.process_nag_tick(cfg),
            DepositEvent::NagReceived(event) => {
                let sm_event = DepositEvent::NagReceived(event.clone());
                self.process_nag_received(event)
                    .map_err(|err| soften_peer_event_error(sm_event, err))
            }
        }
    }
}

/// The output of the Deposit State Machine after processing an event.
///
/// This is a type alias for [`SMOutput`] specialized to the Deposit State Machine's
/// duty and signal types. This ensures that the Deposit SM can only emit [`DepositDuty`]
/// duties and [`DepositSignal`] signals.
pub type DSMOutput = SMOutput<DepositDuty, DepositSignal>;

/// Returns whether every operator other than the assignee has supplied its payout partial.
pub(crate) fn has_all_payout_partials(
    operator_idxs: &BTreeSet<OperatorIdx>,
    assignee: OperatorIdx,
    payout_partials: &BTreeMap<OperatorIdx, PartialSignature>,
) -> bool {
    operator_idxs
        .iter()
        .filter(|&&idx| idx != assignee)
        .all(|idx| payout_partials.contains_key(idx))
}

impl DepositSM {
    /// Takes part in a deposit held in [`DepositState::ParticipationPending`].
    ///
    /// The state returns to [`DepositState::Created`], and the graph contexts frozen at
    /// registration are returned for the caller to build this deposit's graphs from. The caller
    /// must persist this machine and the new graphs atomically.
    ///
    /// Returns `None` and changes nothing unless the deposit is pending, so a late decision cannot
    /// revive a deposit that was taken back, aborted or already decided.
    pub fn participate(&mut self) -> Option<Vec<GraphSMCtx>> {
        if !matches!(self.state, DepositState::ParticipationPending { .. }) {
            return None;
        }
        // Move the pending fields out instead of cloning the graph contexts.
        let DepositState::ParticipationPending {
            deposit_transaction,
            last_block_height,
            graph_contexts,
        } = std::mem::replace(&mut self.state, DepositState::ParticipationDeclined)
        else {
            unreachable!("checked above that the deposit is pending");
        };
        self.state = DepositState::new(deposit_transaction, last_block_height);
        Some(graph_contexts)
    }

    /// Declines a deposit held in [`DepositState::ParticipationPending`].
    ///
    /// The state becomes the terminal [`DepositState::ParticipationDeclined`]: the deposit index
    /// stays allocated and nothing is ever signed for it. Returns whether the state changed; a
    /// late decision leaves any other state alone.
    pub fn decline_participation(&mut self) -> bool {
        if !matches!(self.state, DepositState::ParticipationPending { .. }) {
            return false;
        }
        self.state = DepositState::ParticipationDeclined;
        true
    }

    /// Creates a new [`DepositSM`] using the provided configuration and deposit data.
    ///
    /// The state machine starts in [`DepositState::Created`] by constructing an initial
    /// [`DepositState`] via [`DepositState::new`]. `operator_table` must be the membership of
    /// `covenant`.
    pub fn new(
        bridge_cfg: Arc<DepositSMCfg>,
        covenant: CovenantId,
        operator_table: OperatorTable,
        deposit_data: DepositData,
        depositor_pubkey: XOnlyPublicKey,
        drt_output_amount: Amount,
        block_height: BitcoinBlockHeight,
    ) -> Self {
        let network = bridge_cfg.network();
        let deposit_amount = bridge_cfg.deposit_amount();
        let deposit_time_lock = relative::Height::from_height(bridge_cfg.recovery_delay);
        let n_of_n_pubkey = operator_table.aggregated_btc_key().x_only_public_key().0;

        let deposit_request_connetor = DepositRequestConnector::new(
            bridge_cfg.network,
            n_of_n_pubkey,
            depositor_pubkey,
            deposit_time_lock,
            drt_output_amount,
        );
        let non_connector = NOfNConnector::new(network, n_of_n_pubkey, deposit_amount);

        let deposit_idx = deposit_data.deposit_idx;
        let deposit_request_outpoint = deposit_data.deposit_request_outpoint;
        let deposit_tx = DepositTx::new(deposit_data, non_connector, deposit_request_connetor);

        let deposit_outpoint =
            OutPoint::new(deposit_tx.as_ref().compute_txid(), DepositTx::DEPOSIT_VOUT);
        let context = DepositSMCtx {
            covenant,
            deposit_idx,
            deposit_request_outpoint,
            deposit_outpoint,
            operator_table,
        };

        DepositSM {
            context,
            state: DepositState::new(deposit_tx, block_height),
        }
    }

    /// Declines this deposit request under the node's deposit cap.
    ///
    /// Meant for a machine fresh out of [`DepositSM::new`]: the context is kept, so the deposit
    /// index and outpoints still match every other operator's, but the state becomes
    /// [`DepositState::Skipped`] and nothing is ever signed or emitted for it.
    pub fn into_skipped(self) -> Self {
        debug_assert!(
            matches!(self.state, DepositState::Created { .. }),
            "only a freshly created deposit request can be skipped"
        );
        DepositSM {
            state: DepositState::Skipped,
            ..self
        }
    }

    /// Holds this deposit request until a local policy decides whether this node takes part.
    ///
    /// Meant for a machine fresh out of [`DepositSM::new`], like [`Self::into_skipped`]: the
    /// context is kept, so the deposit index and outpoints still match every other operator's.
    /// `graph_contexts` freezes the covenant and stake bindings that [`Self::participate`] later
    /// hands back, so a delayed decision cannot bind the deposit to a newer covenant or stake.
    ///
    /// # Panics
    ///
    /// If the deposit is not freshly created: not in [`DepositState::Created`], or with graphs
    /// already linked.
    pub fn into_participation_pending(self, graph_contexts: Vec<GraphSMCtx>) -> Self {
        let DepositState::Created {
            deposit_transaction,
            last_block_height,
            claim_txids,
        } = self.state
        else {
            panic!("only a freshly created deposit request can wait for a participation decision");
        };
        assert!(
            claim_txids.is_empty(),
            "a participation decision precedes any graph"
        );
        DepositSM {
            state: DepositState::ParticipationPending {
                deposit_transaction,
                last_block_height,
                graph_contexts,
            },
            ..self
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
