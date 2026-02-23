//! This module handles routing of cross-state-machine signals within the `strata-bridge`.

use strata_bridge_sm::{
    deposit::events::DepositEvent,
    graph::events::GraphEvent,
    signals::{DepositSignal, DepositToGraph, GraphSignal, GraphToDeposit, Signal},
};

use crate::{sm_registry::SMRegistry, sm_types::{SMEvent, SMId}};

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
