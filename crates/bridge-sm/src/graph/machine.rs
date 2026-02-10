//! The Game State Machine (GSM).

use std::sync::Arc;

use crate::{
    graph::{
        config::GraphSMCfg, context::GraphSMCtx, duties::GraphDuty, errors::GSMError,
        events::GraphEvent, state::GraphState,
    },
    signals::GraphSignal,
    state_machine::{SMOutput, StateMachine},
};

/// The State Machine that tracks the state of a deposit utxo at any given time (including the state
/// of cooperative payout process)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSM {
    /// Context associated with this Graph State Machine instance.
    pub context: GraphSMCtx,
    /// The current state of the Deposit State Machine.
    pub state: GraphState,
}

impl StateMachine for DepositSM {
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
            GraphEvent::GraphDataProduced(graph_data) => self.process_graph_data(graph_data),
            GraphEvent::AdaptorsVerified(adaptors) => {
                self.process_adaptors_verification(adaptors)
            }
            GraphEvent::NonceReceived(nonce_event) => self.process_nonces(cfg, nonce_event),
            GraphEvent::PartialReceived(partial_event) => {
                self.process_partials(cfg, partial_event)
            }
            GraphEvent::WithdrawalAssigned(assignment) => self.process_assignment(assignment),
            GraphEvent::FulfillmentConfirmed(fulfillment) => {
                self.process_fulfillment(fulfillment)
            }
            GraphEvent::ClaimConfirmed(claim) => self.process_claim(claim),
            GraphEvent::ContestConfirmed(contest) => self.process_contest(contest),
            GraphEvent::BridgeProofConfirmed(bridge_proof) => {
                self.process_bridge_proof(bridge_proof)
            }
            GraphEvent::BridgeProofTimeoutConfirmed(timeout) => {
                self.process_bridge_proof_timeout(timeout)
            }
            GraphEvent::CounterProofConfirmed(counterproof) => {
                self.process_counterproof(counterproof)
            }
            GraphEvent::CounterProofAckConfirmed(ack) => {
                self.process_counterproof_ack(ack)
            }
            GraphEvent::CounterProofNackConfirmed(nack) => {
                self.process_counterproof_nack(nack)
            }
            GraphEvent::SlashConfirmed(slash) => self.process_slash(slash),
            GraphEvent::PayoutConfirmed(payout) => self.process_payout(payout),
            GraphEvent::PayoutConnectorSpent(connector_spent) => {
                self.process_payout_connector_spent(connector_spent)
            }
            GraphEvent::NewBlock(_new_block) => todo!(),
        }
    }
}

/// The output of the Graph State Machine after processing an event.
///
/// This is a type alias for [`SMOutput`] specialized to the Graph State Machine's
/// duty and signal types. This ensures that the Graph SM can only emit [`GraphDuty`]
/// duties and [`GraphSignal`] signals.
pub type GSMOutput = SMOutput<GraphDuty, GraphSignal>;

impl DepositSM {
    /// Returns a reference to the current state of the Graph State Machine.
    pub const fn state(&self) -> &GraphState {
        &self.state
    }

    /// Returns a mutable reference to the current state of the Graph State Machine.
    pub const fn state_mut(&mut self) -> &mut GraphState {
        &mut self.state
    }
}
