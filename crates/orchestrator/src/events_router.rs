//! This component is responsible for routing messages emitted from [`EventsMux`] to the appropriate
//! state machines in the [`SMRegistry`] for processing.
//!
//! [`EventsMux`]: crate::events_mux::EventsMux

use strata_bridge_p2p_types2::{MuSig2Nonce, MuSig2Partial, UnsignedGossipsubMsg};
use strata_bridge_p2p_wire::p2p::v1::GetMessageRequest;

use crate::{
    events_mux::UnifiedEvent,
    sm_registry::{SMId, SMRegistry},
};

/// Routes all self-contained events to a target state machine based on message content and context.
/// This is the single entrypoint for the `events_router` component.
///
/// A self-contained event is an event that carries all the necessary information on it for routing
/// it to a specific state machine (for example, assignments, p2p messages, etc.).
pub fn route(event: &UnifiedEvent, registry: &SMRegistry) -> Vec<SMId> {
    match event {
        // handled outside this component as it falls under the domain knowledge of the state
        // machines
        UnifiedEvent::Block(_block_event) => Vec::new(),
        // handled outside this component as this is not state machine specific, it's a signal to
        // the orchestrator to shutdown, so we don't route it to any state machine
        UnifiedEvent::Shutdown(_sender) => Vec::new(),
        // relevant to all state machines
        UnifiedEvent::NagTick | UnifiedEvent::RetryTick => registry.get_all_ids(),

        // Each assignment targets one DepositSM and all GraphSMs for that deposit (one per
        // operator).
        UnifiedEvent::Assignment(entries) => entries
            .iter()
            .flat_map(|entry| {
                let deposit_idx = entry.deposit_idx();
                let graph_ids = registry
                    .get_graph_ids()
                    .into_iter()
                    .filter(move |gidx| gidx.deposit == deposit_idx)
                    .map(SMId::Graph);

                [SMId::Deposit(deposit_idx)].into_iter().chain(graph_ids)
            })
            .collect(),

        UnifiedEvent::OuroborosMessage(unsigned_gossipsub_msg) => {
            route_gossipsub_msg(registry, unsigned_gossipsub_msg)
        }
        UnifiedEvent::OuroborosRequest(request) => route_p2p_request(registry, request),
        UnifiedEvent::GossipMessage(gossipsub_msg) => {
            route_gossipsub_msg(registry, &gossipsub_msg.unsigned)
        }
        UnifiedEvent::ReqRespRequest { request, .. } => route_p2p_request(registry, request),
    }
}

fn route_gossipsub_msg(
    registry: &SMRegistry,
    unsigned_gossip_msg: &UnsignedGossipsubMsg,
) -> Vec<SMId> {
    let sm_id = match unsigned_gossip_msg {
        UnsignedGossipsubMsg::PayoutDescriptorExchange { deposit_idx, .. } => {
            SMId::Deposit(*deposit_idx)
        }
        UnsignedGossipsubMsg::Musig2NoncesExchange(musig2_nonce) => match musig2_nonce {
            MuSig2Nonce::Deposit { deposit_idx, .. } => SMId::Deposit(*deposit_idx),
            MuSig2Nonce::Payout { deposit_idx, .. } => SMId::Deposit(*deposit_idx),
            MuSig2Nonce::Graph { graph_idx, .. } => SMId::Graph(*graph_idx),
        },
        UnsignedGossipsubMsg::Musig2SignaturesExchange(musig2_partial) => match musig2_partial {
            MuSig2Partial::Deposit { deposit_idx, .. } => SMId::Deposit(*deposit_idx),
            MuSig2Partial::Payout { deposit_idx, .. } => SMId::Deposit(*deposit_idx),
            MuSig2Partial::Graph { graph_idx, .. } => SMId::Graph(*graph_idx),
        },
    };

    if registry.contains_id(&sm_id) {
        vec![sm_id]
    } else {
        vec![]
    }
}

fn route_p2p_request(
    _registry: &SMRegistry,
    _get_message_request: &GetMessageRequest,
) -> Vec<SMId> {
    todo!("@Rajil1213 implement routing logic for requests once we have new types")
}
