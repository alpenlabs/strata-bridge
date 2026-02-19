//! This component tracks all the state machines in `strata-bridge`.

use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};

use strata_bridge_primitives::types::{DepositIdx, GraphIdx};
use strata_bridge_sm::{deposit::machine::DepositSM, graph::machine::GraphSM};

/// The unique identifier for a state machine in `strata-bridge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SMId {
    /// IDs the state machine responsible for processing a deposit with the given index.
    Deposit(DepositIdx),
    /// IDs the state machine responsible for processing a graph with the given index.
    Graph(GraphIdx),
}

/// An immutable reference to a state machine in the registry.
#[derive(Debug, Clone)]
pub enum SMRef<'sm> {
    /// A reference to the state machine responsible for processing a deposit.
    Deposit(&'sm DepositSM),
    /// A reference to the state machine responsible for processing a graph.
    Graph(&'sm GraphSM),
}

impl Deref for SMRef<'_> {
    type Target = dyn std::fmt::Debug;

    fn deref(&self) -> &Self::Target {
        match self {
            SMRef::Deposit(sm) => *sm,
            SMRef::Graph(sm) => *sm,
        }
    }
}

/// A mutable reference to a state machine in the registry.
#[derive(Debug)]
pub enum SMRefMut<'sm> {
    /// A mutable reference to the state machine responsible for processing a deposit.
    Deposit(&'sm mut DepositSM),
    /// A mutable reference to the state machine responsible for processing a graph.
    Graph(&'sm mut GraphSM),
}

impl Deref for SMRefMut<'_> {
    type Target = dyn std::fmt::Debug;
    fn deref(&self) -> &Self::Target {
        match self {
            SMRefMut::Deposit(sm) => *sm,
            SMRefMut::Graph(sm) => *sm,
        }
    }
}

impl DerefMut for SMRefMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            SMRefMut::Deposit(sm) => *sm,
            SMRefMut::Graph(sm) => *sm,
        }
    }
}

/// The registry that holds all the active state machines in `strata-bridge`.
#[derive(Debug, Default, Clone)]
pub struct SMRegistry {
    /// The state machines responsible for processing deposits, indexed by their deposit index.
    deposits: BTreeMap<DepositIdx, DepositSM>,
    /// The state machines responsible for processing graphs, indexed by their graph index.
    // NOTE: (@Rajil1213) if performance becomes an issue when looking up graph state machines by
    // deposit index, change this to a `BTreeMap<DepositIdx, BTreeMap<OperatorIdx, GraphSM>>` or
    // maintain a separate index for that mapping.
    graphs: BTreeMap<GraphIdx, GraphSM>,
}

impl SMRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets a reference to the state machine with the given ID, if it exists in the registry.
    pub fn get(&self, id: &SMId) -> Option<SMRef<'_>> {
        match id {
            SMId::Deposit(deposit_idx) => self.deposits.get(deposit_idx).map(SMRef::Deposit),
            SMId::Graph(graph_idx) => self.graphs.get(graph_idx).map(SMRef::Graph),
        }
    }

    /// Gets a mutable reference to the state machine with the given ID, if it exists in the
    /// registry.
    pub fn get_mut(&mut self, id: &SMId) -> Option<SMRefMut<'_>> {
        match id {
            SMId::Deposit(deposit_idx) => self.deposits.get_mut(deposit_idx).map(SMRefMut::Deposit),
            SMId::Graph(graph_idx) => self.graphs.get_mut(graph_idx).map(SMRefMut::Graph),
        }
    }

    /// Gets a list of IDs of all deposit state machines currently in the registry.
    pub fn get_deposit_ids(&self) -> Vec<DepositIdx> {
        self.deposits.keys().copied().collect()
    }

    /// Gets a list of IDs of all graph state machines currently in the registry.
    pub fn get_graph_ids(&self) -> Vec<GraphIdx> {
        self.graphs.keys().copied().collect()
    }

    /// Gets the IDs of all the state machines currently in the registry.
    pub fn get_all_ids(&self) -> Vec<SMId> {
        self.deposits
            .keys()
            .map(|deposit_idx| SMId::Deposit(*deposit_idx))
            .chain(self.graphs.keys().map(|graph_idx| SMId::Graph(*graph_idx)))
            .collect()
    }

    /// Checks if an ID is present in the registry.
    pub fn contains_id(&self, id: &SMId) -> bool {
        match id {
            SMId::Deposit(deposit_idx) => self.deposits.contains_key(deposit_idx),
            SMId::Graph(graph_idx) => self.graphs.contains_key(graph_idx),
        }
    }

    /// Inserts a new deposit state machine into the registry with the given deposit index.
    ///
    /// If a state machine with the same [`DepositIdx`] already exists, it will be overwritten.
    pub fn insert_deposit(&mut self, deposit_idx: DepositIdx, sm: DepositSM) {
        self.deposits.insert(deposit_idx, sm);
    }

    /// Inserts a new graph state machine into the registry with the given graph index.
    ///
    /// If a state machine with the same [`GraphIdx`] already exists, it will be overwritten.
    pub fn insert_graph(&mut self, graph_idx: GraphIdx, sm: GraphSM) {
        self.graphs.insert(graph_idx, sm);
    }
}
