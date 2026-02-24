//! This component is responsible for routing messages emitted from [`EventsMux`] to the appropriate
//! state machines in the [`SMRegistry`] for processing.
//!
//! [`EventsMux`]: crate::events_mux::EventsMux

use strata_bridge_p2p_types2::{MuSig2Nonce, MuSig2Partial, UnsignedGossipsubMsg};
use strata_bridge_p2p_wire::p2p::v1::GetMessageRequest;

use crate::{events_mux::UnifiedEvent, sm_registry::SMRegistry, sm_types::SMId};

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

#[cfg(test)]
mod tests {
    use strata_asm_proto_bridge_v1::AssignmentEntry;
    use strata_bridge_p2p_types2::{GraphIdx, PayoutDescriptor, PubNonce};
    use strata_bridge_test_utils::{
        arbitrary_generator::ArbitraryGenerator, musig2::generate_pubnonce,
    };

    use super::*;
    use crate::testing::{
        N_TEST_OPERATORS, insert_deposit_with_graphs, test_empty_registry, test_populated_registry,
    };

    // ===== Helpers =====

    fn make_deposit_nonce(deposit_idx: u32) -> UnsignedGossipsubMsg {
        let nonce: PubNonce = generate_pubnonce().into();
        UnsignedGossipsubMsg::Musig2NoncesExchange(MuSig2Nonce::Deposit { deposit_idx, nonce })
    }

    fn make_graph_nonce(deposit: u32, operator: u32) -> UnsignedGossipsubMsg {
        let nonce: PubNonce = generate_pubnonce().into();
        UnsignedGossipsubMsg::Musig2NoncesExchange(MuSig2Nonce::Graph {
            graph_idx: GraphIdx { deposit, operator },
            nonces: vec![nonce],
        })
    }

    fn make_payout_descriptor(deposit_idx: u32) -> UnsignedGossipsubMsg {
        UnsignedGossipsubMsg::PayoutDescriptorExchange {
            deposit_idx,
            operator_idx: 0,
            operator_desc: PayoutDescriptor::new(vec![0xDE, 0xAD]),
        }
    }

    // ===== route() tests for non-gossip events =====

    #[test]
    fn route_nag_tick_returns_all_ids() {
        let registry = test_populated_registry(2);
        let all_ids = registry.get_all_ids();

        let routed = route(&UnifiedEvent::NagTick, &registry);
        assert_eq!(routed, all_ids);
    }

    #[test]
    fn route_retry_tick_returns_all_ids() {
        let registry = test_populated_registry(2);
        let all_ids = registry.get_all_ids();

        let routed = route(&UnifiedEvent::RetryTick, &registry);
        assert_eq!(routed, all_ids);
    }

    #[test]
    fn route_tick_empty_registry() {
        let registry = test_empty_registry();

        let routed = route(&UnifiedEvent::NagTick, &registry);
        assert!(routed.is_empty());
    }

    // ===== route_gossipsub_msg() tests =====

    #[test]
    fn route_gossip_deposit_nonce_known() {
        let registry = test_populated_registry(1);
        let msg = make_deposit_nonce(0);

        let routed = route_gossipsub_msg(&registry, &msg);
        assert_eq!(routed, vec![SMId::Deposit(0)]);
    }

    #[test]
    fn route_gossip_deposit_nonce_unknown() {
        let registry = test_populated_registry(1);
        let msg = make_deposit_nonce(99);

        let routed = route_gossipsub_msg(&registry, &msg);
        assert!(routed.is_empty());
    }

    #[test]
    fn route_gossip_graph_nonce() {
        let registry = test_populated_registry(1);
        let msg = make_graph_nonce(0, 1);

        let routed = route_gossipsub_msg(&registry, &msg);
        assert_eq!(
            routed,
            vec![SMId::Graph(GraphIdx {
                deposit: 0,
                operator: 1
            })]
        );
    }

    #[test]
    fn route_gossip_graph_nonce_unknown() {
        let registry = test_populated_registry(1);
        let msg = make_graph_nonce(99, 0);

        let routed = route_gossipsub_msg(&registry, &msg);
        assert!(routed.is_empty());
    }

    #[test]
    fn route_gossip_payout_descriptor() {
        let registry = test_populated_registry(1);
        let msg = make_payout_descriptor(0);

        let routed = route_gossipsub_msg(&registry, &msg);
        assert_eq!(routed, vec![SMId::Deposit(0)]);
    }

    // ===== Assignment routing tests =====

    #[test]
    fn route_assignment_deposit_and_graphs() {
        // Construct an AssignmentEntry using arbitrary, observe its deposit_idx,
        // then build the registry around it.
        let mut arb = ArbitraryGenerator::new();
        let entry: AssignmentEntry = arb.generate();
        let dep_idx = entry.deposit_idx();

        let mut registry = test_empty_registry();
        insert_deposit_with_graphs(&mut registry, dep_idx);

        let event = UnifiedEvent::Assignment(vec![entry]);
        let routed = route(&event, &registry);

        // Should include the deposit SM + N_TEST_OPERATORS graph SMs
        assert!(routed.contains(&SMId::Deposit(dep_idx)));
        for op in 0..N_TEST_OPERATORS as u32 {
            assert!(routed.contains(&SMId::Graph(GraphIdx {
                deposit: dep_idx,
                operator: op,
            })));
        }
        assert_eq!(routed.len(), 1 + N_TEST_OPERATORS);
    }

    #[test]
    fn route_assignment_multiple_entries() {
        let mut registry = test_empty_registry();
        let mut arb = ArbitraryGenerator::new();

        let entry1: AssignmentEntry = arb.generate();
        let dep1 = entry1.deposit_idx();
        insert_deposit_with_graphs(&mut registry, dep1);

        let entry2: AssignmentEntry = arb.generate();
        let dep2 = entry2.deposit_idx();
        if dep2 != dep1 {
            insert_deposit_with_graphs(&mut registry, dep2);
        }
        let event = UnifiedEvent::Assignment(vec![entry1, entry2]);
        let routed = route(&event, &registry);

        // At minimum, each entry produces deposit + graphs
        assert!(routed.contains(&SMId::Deposit(dep1)));
        assert!(routed.contains(&SMId::Deposit(dep2)));
    }
}
