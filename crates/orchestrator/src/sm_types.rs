//! Unified types for state machine identity, operator resolution, events, and processing output.

use std::{fmt::Display, ops::Deref};

use strata_bridge_p2p_types2::P2POperatorPubKey;
use strata_bridge_primitives::types::{DepositIdx, GraphIdx};
use strata_bridge_sm::{
    deposit::{duties::DepositDuty, events::DepositEvent},
    graph::{duties::GraphDuty, events::GraphEvent},
};

/// The unique identifier for a state machine in `strata-bridge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SMId {
    /// IDs the state machine responsible for processing a deposit with the given index.
    Deposit(DepositIdx),
    /// IDs the state machine responsible for processing a graph with the given index.
    Graph(GraphIdx),
}

impl From<DepositIdx> for SMId {
    fn from(deposit_idx: DepositIdx) -> Self {
        SMId::Deposit(deposit_idx)
    }
}

impl From<GraphIdx> for SMId {
    fn from(graph_idx: GraphIdx) -> Self {
        SMId::Graph(graph_idx)
    }
}

impl Display for SMId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SMId::Deposit(deposit_idx) => write!(f, "Deposit({})", deposit_idx),
            SMId::Graph(graph_idx) => write!(
                f,
                "Graph(deposit: {}, operator: {})",
                graph_idx.deposit, graph_idx.operator
            ),
        }
    }
}

/// Identifies which operator to resolve from a state machine's operator table.
#[derive(Debug)]
pub enum OperatorKey<'a> {
    /// Our own operator (point-of-view).
    Pov,
    /// An operator identified by their peer P2P public key.
    Peer(&'a P2POperatorPubKey),
}

/// Wrapper for state-machine-specific events.
#[derive(Debug, Clone)]
pub enum SMEvent {
    /// An event related to the deposit state machine.
    Deposit(Box<DepositEvent>),
    /// An event related to the graph state machine.
    Graph(Box<GraphEvent>),
}

impl Deref for SMEvent {
    type Target = dyn std::fmt::Debug;

    fn deref(&self) -> &Self::Target {
        match self {
            SMEvent::Deposit(event) => event,
            SMEvent::Graph(event) => event,
        }
    }
}

impl Display for SMEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SMEvent::Deposit(event) => write!(f, "DepositEvent({event})"),
            SMEvent::Graph(event) => write!(f, "GraphEvent({event})"),
        }
    }
}

impl From<DepositEvent> for SMEvent {
    fn from(event: DepositEvent) -> Self {
        SMEvent::Deposit(Box::new(event))
    }
}

impl From<GraphEvent> for SMEvent {
    fn from(event: GraphEvent) -> Self {
        SMEvent::Graph(Box::new(event))
    }
}

/// A wrapper for holding all the different types of duties that a state machine can emit after a
/// successful STF.
#[derive(Debug, Clone)]
pub enum UnifiedDuty {
    /// A duty related to a deposit.
    Deposit(DepositDuty),
    /// A duty related to the game graph.
    Graph(GraphDuty),
}
