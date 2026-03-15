//! This module handles routing of cross-state-machine signals within the `strata-bridge`.

use strata_bridge_sm::{
    deposit::events::DepositEvent,
    graph::events::GraphEvent,
    signals::{DepositSignal, DepositToGraph, GraphSignal, GraphToDeposit, Signal},
};

use crate::{
    sm_registry::SMRegistry,
    sm_types::{SMEvent, SMId},
};

/// Routes a given signal to the appropriate state machine(s) based on the provided registry and
/// returns a mapping of state machine IDs to the events that should be processed by those state
/// machines as a result of the signal.
pub fn route_signal(registry: &SMRegistry, signal: Signal) -> Vec<(SMId, SMEvent)> {
    match signal {
        Signal::FromDeposit(deposit_signal) => match deposit_signal {
            DepositSignal::ToGraph(deposit_to_graph) => match deposit_to_graph {
                msg @ DepositToGraph::CooperativePayoutFailed { graph_idx, .. } => {
                    let event: SMEvent = GraphEvent::DepositMessage(msg).into();

                    registry
                        .get_graph_ids()
                        .into_iter()
                        .filter(|id| *id == graph_idx)
                        .map(|graph_id| (graph_id.into(), event.clone()))
                        .collect()
                }
            },
        },

        Signal::FromGraph(graph_signal) => match graph_signal {
            GraphSignal::ToDeposit(graph_to_deposit) => match graph_to_deposit {
                msg @ GraphToDeposit::GraphAvailable { deposit_idx, .. } => {
                    let event: SMEvent = DepositEvent::GraphMessage(msg).into();

                    registry
                        .get_deposit_ids()
                        .into_iter()
                        .filter(|idx| *idx == deposit_idx)
                        .map(|deposit_id| (deposit_id.into(), event.clone()))
                        .collect()
                }
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use strata_bridge_primitives::types::GraphIdx;
    use strata_bridge_test_utils::prelude::generate_txid;

    use super::*;
    use crate::testing::test_populated_registry;

    #[test]
    fn cooperative_payout_failed_routes_to_specific_graph() {
        let registry = test_populated_registry(2);
        let target_graph = GraphIdx {
            deposit: 0,
            operator: 1,
        };
        let signal = Signal::FromDeposit(DepositSignal::ToGraph(
            DepositToGraph::CooperativePayoutFailed {
                graph_idx: target_graph,
                assignee: 1,
            },
        ));

        let targets = route_signal(&registry, signal);

        assert_eq!(targets.len(), 1);
        match &targets[0].0 {
            SMId::Graph(gidx) => assert_eq!(*gidx, target_graph),
            other => panic!("expected Graph SM ID, got {other}"),
        }
    }

    #[test]
    fn cooperative_payout_failed_no_matching_graph() {
        let registry = test_populated_registry(1);
        let signal = Signal::FromDeposit(DepositSignal::ToGraph(
            DepositToGraph::CooperativePayoutFailed {
                graph_idx: GraphIdx {
                    deposit: 99,
                    operator: 0,
                },
                assignee: 0,
            },
        ));

        let targets = route_signal(&registry, signal);
        assert!(targets.is_empty());
    }

    #[test]
    fn cooperative_payout_failed_ignores_other_graphs() {
        let registry = test_populated_registry(3);
        let target_graph = GraphIdx {
            deposit: 1,
            operator: 2,
        };
        let signal = Signal::FromDeposit(DepositSignal::ToGraph(
            DepositToGraph::CooperativePayoutFailed {
                graph_idx: target_graph,
                assignee: 2,
            },
        ));

        let targets = route_signal(&registry, signal);

        assert_eq!(targets.len(), 1);
        match &targets[0].0 {
            SMId::Graph(gidx) => {
                assert_eq!(*gidx, target_graph);
            }
            other => panic!("expected Graph SM ID, got {other}"),
        }
    }

    #[test]
    fn graph_available_routes_to_deposit() {
        let registry = test_populated_registry(2);
        let signal = Signal::FromGraph(GraphSignal::ToDeposit(GraphToDeposit::GraphAvailable {
            claim_txid: generate_txid(),
            deposit_idx: 1,
            operator_idx: 0,
        }));

        let targets = route_signal(&registry, signal);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, SMId::Deposit(1));
    }

    #[test]
    fn graph_available_no_matching_deposit() {
        let registry = test_populated_registry(1);
        let signal = Signal::FromGraph(GraphSignal::ToDeposit(GraphToDeposit::GraphAvailable {
            claim_txid: generate_txid(),
            deposit_idx: 99,
            operator_idx: 0,
        }));

        let targets = route_signal(&registry, signal);
        assert!(targets.is_empty());
    }
}
