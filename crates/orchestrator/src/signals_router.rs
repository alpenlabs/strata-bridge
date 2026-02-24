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
                msg @ DepositToGraph::CooperativePayoutFailed { deposit_idx, .. } => {
                    let event: SMEvent = GraphEvent::DepositMessage(msg).into();

                    registry
                        .get_graph_ids()
                        .into_iter()
                        .filter(|graph_id| graph_id.deposit == deposit_idx)
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
    use strata_bridge_primitives::types::OperatorIdx;
    use strata_bridge_test_utils::prelude::generate_txid;

    use super::*;
    use crate::testing::{N_TEST_OPERATORS, test_populated_registry};

    #[test]
    fn cooperative_payout_failed_routes_to_matching_graphs() {
        let registry = test_populated_registry(2);
        let signal = Signal::FromDeposit(DepositSignal::ToGraph(
            DepositToGraph::CooperativePayoutFailed {
                deposit_idx: 0,
                assignee: 0,
            },
        ));

        let targets = route_signal(&registry, signal);

        assert_eq!(targets.len(), N_TEST_OPERATORS);
        for (id, _event) in &targets {
            match id {
                SMId::Graph(gidx) => assert_eq!(gidx.deposit, 0),
                _ => panic!("expected Graph SM ID, got {id}"),
            }
        }
    }

    #[test]
    fn cooperative_payout_failed_no_matching_graphs() {
        let registry = test_populated_registry(1);
        let signal = Signal::FromDeposit(DepositSignal::ToGraph(
            DepositToGraph::CooperativePayoutFailed {
                deposit_idx: 99,
                assignee: 0,
            },
        ));

        let targets = route_signal(&registry, signal);
        assert!(targets.is_empty());
    }

    #[test]
    fn cooperative_payout_failed_ignores_other_deposits() {
        let registry = test_populated_registry(3);
        let signal = Signal::FromDeposit(DepositSignal::ToGraph(
            DepositToGraph::CooperativePayoutFailed {
                deposit_idx: 1,
                assignee: 0,
            },
        ));

        let targets = route_signal(&registry, signal);

        // Only graphs for deposit 1, not 0 or 2.
        assert_eq!(targets.len(), N_TEST_OPERATORS);
        for (id, _event) in &targets {
            match id {
                SMId::Graph(gidx) => {
                    assert_eq!(gidx.deposit, 1);
                    assert!(gidx.operator < N_TEST_OPERATORS as OperatorIdx);
                }
                _ => panic!("expected Graph SM ID, got {id}"),
            }
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
