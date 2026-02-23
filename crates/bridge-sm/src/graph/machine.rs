//! The Game State Machine (GSM).

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_bridge_tx_graph2::game_graph::{DepositParams, GameData, GameGraph};

use crate::{
    graph::{
        config::GraphSMCfg,
        context::GraphSMCtx,
        duties::GraphDuty,
        errors::{GSMError, GSMResult},
        events::GraphEvent,
        state::GraphState,
    },
    signals::GraphSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphSM {
    /// Context associated with this Graph State Machine instance.
    pub context: GraphSMCtx,
    /// The current state of the Graph State Machine.
    pub state: GraphState,
}

impl StateMachine for GraphSM {
    type Config = Arc<GraphSMCfg>;
    type Duty = GraphDuty;
    type OutgoingSignal = GraphSignal;
    type Event = GraphEvent;
    type Error = GSMError;

    fn process_event(
        &mut self,
        cfg: Self::Config,
        event: Self::Event,
    ) -> Result<SMOutput<Self::Duty, Self::OutgoingSignal>, Self::Error> {
        match event {
            GraphEvent::GraphDataProduced(graph_data) => self.process_graph_data(cfg, graph_data),
            GraphEvent::AdaptorsVerified(adaptors) => {
                self.process_adaptors_verification(cfg, adaptors)
            }
            GraphEvent::NonceReceived(nonce_event) => self.process_nonce_received(cfg, nonce_event),
            GraphEvent::PartialReceived(partial_event) => {
                self.process_partial_received(cfg, partial_event)
            }
            GraphEvent::WithdrawalAssigned(assignment) => self.process_assignment(assignment),
            GraphEvent::FulfillmentConfirmed(fulfillment) => {
                self.process_fulfillment(cfg, fulfillment)
            }
            GraphEvent::ClaimConfirmed(claim) => self.process_claim(claim),
            GraphEvent::ContestConfirmed(_contest) => todo!(),
            GraphEvent::BridgeProofConfirmed(_bridge_proof) => todo!(),
            GraphEvent::BridgeProofTimeoutConfirmed(_timeout) => todo!(),
            GraphEvent::CounterProofConfirmed(_counterproof) => todo!(),
            GraphEvent::CounterProofAckConfirmed(_ack) => todo!(),
            GraphEvent::CounterProofNackConfirmed(_nack) => todo!(),
            GraphEvent::SlashConfirmed(_slash) => todo!(),
            GraphEvent::PayoutConfirmed(payout) => self.process_payout(payout),
            GraphEvent::PayoutConnectorSpent(_connector_spent) => todo!(),
            GraphEvent::NewBlock(new_block) => self.notify_new_block(cfg, new_block),
        }
    }
}

/// The output of the Graph State Machine after processing an event.
///
/// This is a type alias for [`SMOutput`] specialized to the Graph State Machine's
/// duty and signal types. This ensures that the Graph SM can only emit [`GraphDuty`]
/// duties and [`GraphSignal`] signals.
pub type GSMOutput = SMOutput<GraphDuty, GraphSignal>;

impl GraphSM {
    /// Creates a new [`GraphSM`] using the provided context and initial block height.
    ///
    /// The state machine starts in [`GraphState::Created`] by constructing the
    /// initial [`GraphState`] via [`GraphState::new`].
    pub const fn new(context: GraphSMCtx, block_height: BitcoinBlockHeight) -> Self {
        Self {
            context,
            state: GraphState::new(block_height),
        }
    }

    /// Returns a reference to the Graph State Machine params.
    pub const fn context(&self) -> &GraphSMCtx {
        &self.context
    }

    /// Returns a reference to the current state of the Graph State Machine.
    pub const fn state(&self) -> &GraphState {
        &self.state
    }

    /// Returns a mutable reference to the current state of the Graph State Machine.
    pub const fn state_mut(&mut self) -> &mut GraphState {
        &mut self.state
    }

    /// Checks that the operator index exists, otherwise returns `GSMError::Rejected`.
    pub(super) fn check_operator_idx<E>(&self, operator_idx: u32, inner_event: &E) -> GSMResult<()>
    where
        E: Clone + Into<GraphEvent>,
    {
        if self.context().operator_table().contains_idx(&operator_idx) {
            Ok(())
        } else {
            Err(GSMError::rejected(
                self.state().clone(),
                inner_event.clone().into(),
                format!("Operator index {} not in operator table", operator_idx),
            ))
        }
    }
}

/// Generates the [`GameGraph`] from the [`GraphSM`] config and deposit params.
pub(crate) fn generate_game_graph(
    cfg: &GraphSMCfg,
    ctx: &GraphSMCtx,
    deposit_params: DepositParams,
) -> GameGraph {
    let setup_params = cfg.generate_setup_params(ctx);
    let protocol_params = cfg.game_graph_params;
    let graph_data = GameData {
        protocol: protocol_params,
        setup: setup_params,
        deposit: deposit_params,
    };

    let (game_graph, _) = GameGraph::new(graph_data);
    game_graph
}
