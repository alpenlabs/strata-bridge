//! The state machine registry: stores all active state machines and provides methods for
//! querying, resolving operators, and driving state transitions.

use std::{collections::BTreeMap, sync::Arc};

use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_sm::{
    deposit::{config::DepositSMCfg, machine::DepositSM},
    errors::BridgeSMError,
    graph::{config::GraphSMCfg, machine::GraphSM},
    state_machine::{SMOutput, StateMachine},
};

use crate::{
    errors::{ProcessError, ProcessResult},
    sm_types::{OperatorKey, SMEvent, SMId, UnifiedDuty},
};

/// Static configuration shared by all state machines.
#[derive(Debug, Clone)]
pub struct SMConfig {
    /// Static configuration for all deposit state machines.
    pub deposit: Arc<DepositSMCfg>,
    /// Static configuration for all graph state machines.
    pub graph: Arc<GraphSMCfg>,
}

/// The registry that holds all the active state machines in `strata-bridge`.
#[derive(Debug, Clone)]
pub struct SMRegistry {
    /// Static configuration shared by all state machines.
    cfg: SMConfig,
    /// The state machines responsible for processing deposits, indexed by their deposit index.
    deposits: BTreeMap<DepositIdx, DepositSM>,
    /// The state machines responsible for processing graphs, indexed by their graph index.
    graphs: BTreeMap<DepositIdx, BTreeMap<OperatorIdx, GraphSM>>,
}

impl SMRegistry {
    /// Creates a new empty registry with the given configuration.
    pub const fn new(cfg: SMConfig) -> Self {
        Self {
            cfg,
            deposits: BTreeMap::new(),
            graphs: BTreeMap::new(),
        }
    }

    /// Gets a reference to the registry configuration.
    pub const fn cfg(&self) -> &SMConfig {
        &self.cfg
    }

    /// Gets the total number of deposit state machines currently in the registry.
    pub fn num_deposits(&self) -> usize {
        self.deposits.len()
    }

    /// Gets a list of IDs of all deposit state machines currently in the registry.
    pub fn get_deposit_ids(&self) -> Vec<DepositIdx> {
        self.deposits.keys().copied().collect()
    }

    /// Gets a list of IDs of all operator graph state machines currently in the registry by their
    /// [`DepositIdx`].
    pub fn get_graphs_by_deposit(&self, deposit_idx: &DepositIdx) -> Vec<&GraphSM> {
        self.graphs
            .get(deposit_idx)
            .into_iter()
            .flat_map(|operator_map| operator_map.values())
            .collect()
    }

    /// Gets a list of IDs of all graph state machines currently in the registry.
    pub fn get_graph_ids(&self) -> Vec<GraphIdx> {
        self.graphs
            .iter()
            .flat_map(|(deposit_idx, operator_map)| {
                operator_map.keys().map(move |operator_idx| GraphIdx {
                    deposit: *deposit_idx,
                    operator: *operator_idx,
                })
            })
            .collect()
    }

    /// Gets the IDs of all the state machines currently in the registry.
    pub fn get_all_ids(&self) -> Vec<SMId> {
        self.deposits
            .keys()
            .map(|deposit_idx| SMId::Deposit(*deposit_idx))
            .chain(self.graphs.iter().flat_map(|(deposit_idx, operator_map)| {
                operator_map.keys().map(move |operator_idx| {
                    SMId::Graph(GraphIdx {
                        deposit: *deposit_idx,
                        operator: *operator_idx,
                    })
                })
            }))
            .collect()
    }

    /// Gets a reference to the deposit state machine identified by `id`, if it exists in the
    /// registry.
    pub fn get_deposit(&self, deposit_idx: &DepositIdx) -> Option<&DepositSM> {
        self.deposits.get(deposit_idx)
    }

    /// Gets a reference to the graph state machine identified by `id`, if it exists in the
    /// registry.
    pub fn get_graph(&self, graph_idx: &GraphIdx) -> Option<&GraphSM> {
        self.graphs
            .get(&graph_idx.deposit)?
            .get(&graph_idx.operator)
    }

    /// Returns an iterator over all deposit state machines and their indices.
    pub fn deposits(&self) -> impl Iterator<Item = (&DepositIdx, &DepositSM)> {
        self.deposits.iter()
    }

    /// Returns an iterator over all graph state machines and their indices.
    pub fn graphs(&self) -> impl Iterator<Item = &GraphSM> {
        self.graphs
            .values()
            .flat_map(|operator_map| operator_map.values())
    }

    /// Checks if an ID is present in the registry.
    pub fn contains_id(&self, id: &SMId) -> bool {
        match id {
            SMId::Deposit(deposit_idx) => self.deposits.contains_key(deposit_idx),
            SMId::Graph(graph_idx) => self
                .graphs
                .get(&graph_idx.deposit)
                .is_some_and(|operator_map| operator_map.contains_key(&graph_idx.operator)),
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
        self.graphs
            .entry(graph_idx.deposit)
            .or_default()
            .insert(graph_idx.operator, sm);
    }

    /// Looks up the state machine identified by `id` and resolves the operator index using the
    /// given [`OperatorKey`].
    ///
    /// Returns `None` if the SM is not in the registry or the operator key cannot be resolved.
    pub fn lookup_operator(&self, id: &SMId, key: &OperatorKey<'_>) -> Option<OperatorIdx> {
        let table = match id {
            SMId::Deposit(idx) => self.deposits.get(idx)?.context().operator_table(),
            SMId::Graph(idx) => self
                .graphs
                .get(&idx.deposit)?
                .get(&idx.operator)?
                .context()
                .operator_table(),
        };
        match key {
            OperatorKey::Pov => Some(table.pov_idx()),
            OperatorKey::Peer(p2p_key) => table.p2p_key_to_idx(&(*p2p_key).clone().into()),
        }
    }

    /// Processes an event through the state machine identified by `id`.
    ///
    /// Looks up the SM, matches it against the event variant, runs the state transition, and
    /// returns unified output. The caller does not need to know the concrete SM type.
    pub fn process_event(&mut self, id: &SMId, event: SMEvent) -> ProcessResult {
        match (id, event) {
            (SMId::Deposit(idx), SMEvent::Deposit(deposit_event)) => {
                let sm = self
                    .deposits
                    .get_mut(idx)
                    .ok_or(ProcessError::SMNotFound(*id))?;
                let event = SMEvent::Deposit(deposit_event.clone());
                sm.process_event(self.cfg.deposit.clone(), *deposit_event)
                    .map(|out| SMOutput {
                        duties: out.duties.into_iter().map(UnifiedDuty::Deposit).collect(),
                        signals: out.signals.into_iter().map(Into::into).collect(),
                    })
                    .map_err(|err| sm_to_process_err(id, event, err))
            }

            (SMId::Graph(idx), SMEvent::Graph(graph_event)) => {
                let sm = self
                    .graphs
                    .get_mut(&idx.deposit)
                    .ok_or(ProcessError::SMNotFound(*id))?
                    .get_mut(&idx.operator)
                    .ok_or(ProcessError::SMNotFound(*id))?;

                let event = SMEvent::Graph(graph_event.clone());

                sm.process_event(self.cfg.graph.clone(), *graph_event)
                    .map(|out| SMOutput {
                        duties: out.duties.into_iter().map(UnifiedDuty::Graph).collect(),
                        signals: out.signals.into_iter().map(Into::into).collect(),
                    })
                    .map_err(|err| sm_to_process_err(id, event, err))
            }

            (id, event) => Err(ProcessError::InvalidInvocation(*id, event)),
        }
    }
}

fn sm_to_process_err<S, E>(id: &SMId, event: SMEvent, err: BridgeSMError<S, E>) -> ProcessError
where
    S: std::fmt::Display + std::fmt::Debug,
    E: std::fmt::Display + std::fmt::Debug,
{
    match err {
        BridgeSMError::InvalidEvent { reason, .. } => ProcessError::InvariantViolation(
            *id,
            event.clone(),
            reason.unwrap_or_else(|| "invalid event".to_string()),
        ),
        BridgeSMError::Duplicate { .. } => ProcessError::DuplicateEvent(*id, event.clone()),
        BridgeSMError::Rejected { reason, .. } => {
            ProcessError::EventRejected(*id, event.clone(), reason)
        }
    }
}
