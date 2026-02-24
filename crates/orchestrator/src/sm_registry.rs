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
    // NOTE: (@Rajil1213) if performance becomes an issue when looking up graph state machines by
    // deposit index, change this to a `BTreeMap<DepositIdx, BTreeMap<OperatorIdx, GraphSM>>` or
    // maintain a separate index for that mapping.
    graphs: BTreeMap<GraphIdx, GraphSM>,
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

    /// Gets a reference to the deposit state machine identified by `id`, if it exists in the
    /// registry.
    pub fn get_deposit(&self, deposit_idx: &DepositIdx) -> Option<&DepositSM> {
        self.deposits.get(deposit_idx)
    }

    /// Gets a reference to the graph state machine identified by `id`, if it exists in the
    /// registry.
    pub fn get_graph(&self, graph_idx: &GraphIdx) -> Option<&GraphSM> {
        self.graphs.get(graph_idx)
    }

    /// Returns an iterator over all deposit state machines and their indices.
    pub fn deposits(&self) -> impl Iterator<Item = (&DepositIdx, &DepositSM)> {
        self.deposits.iter()
    }

    /// Returns an iterator over all graph state machines and their indices.
    pub fn graphs(&self) -> impl Iterator<Item = (&GraphIdx, &GraphSM)> {
        self.graphs.iter()
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

    /// Looks up the state machine identified by `id` and resolves the operator index using the
    /// given [`OperatorKey`].
    ///
    /// Returns `None` if the SM is not in the registry or the operator key cannot be resolved.
    pub fn lookup_operator(&self, id: &SMId, key: &OperatorKey<'_>) -> Option<OperatorIdx> {
        let table = match id {
            SMId::Deposit(idx) => self.deposits.get(idx)?.context().operator_table(),
            SMId::Graph(idx) => self.graphs.get(idx)?.context().operator_table(),
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
                    .get_mut(idx)
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

#[cfg(test)]
mod tests {
    use strata_bridge_primitives::types::GraphIdx;
    use strata_bridge_sm::{
        deposit::events::{DepositEvent, NewBlockEvent as DepositNewBlock},
        graph::events::{GraphEvent, NewBlockEvent as GraphNewBlock},
    };

    use super::*;
    use crate::{
        sm_types::OperatorKey,
        testing::{
            N_TEST_OPERATORS, TEST_POV_IDX, test_empty_registry, test_operator_table,
            test_populated_registry,
        },
    };

    // ===== Basic CRUD tests =====

    #[test]
    fn new_registry_is_empty() {
        let registry = test_empty_registry();
        assert_eq!(registry.num_deposits(), 0);
        assert!(registry.get_all_ids().is_empty());
    }

    #[test]
    fn insert_and_get_deposit() {
        let registry = test_populated_registry(1);
        assert!(registry.get_deposit(&0).is_some());
    }

    #[test]
    fn insert_and_get_graph() {
        let registry = test_populated_registry(1);
        let gidx = GraphIdx {
            deposit: 0,
            operator: 0,
        };
        assert!(registry.get_graph(&gidx).is_some());
    }

    #[test]
    fn contains_id_true_for_existing() {
        let registry = test_populated_registry(1);

        assert!(registry.contains_id(&SMId::Deposit(0)));
        assert!(registry.contains_id(&SMId::Graph(GraphIdx {
            deposit: 0,
            operator: 1,
        })));
    }

    #[test]
    fn contains_id_false_for_missing() {
        let registry = test_populated_registry(1);

        assert!(!registry.contains_id(&SMId::Deposit(99)));
        assert!(!registry.contains_id(&SMId::Graph(GraphIdx {
            deposit: 99,
            operator: 0,
        })));
    }

    #[test]
    fn get_all_ids_both_types() {
        let registry = test_populated_registry(1);
        let ids = registry.get_all_ids();

        // 1 deposit + N_TEST_OPERATORS graphs
        assert_eq!(ids.len(), 1 + N_TEST_OPERATORS);

        let has_deposit = ids.iter().any(|id| matches!(id, SMId::Deposit(0)));
        let graph_count = ids.iter().filter(|id| matches!(id, SMId::Graph(_))).count();

        assert!(has_deposit);
        assert_eq!(graph_count, N_TEST_OPERATORS);
    }

    // ===== lookup_operator tests =====

    #[test]
    fn lookup_operator_pov() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(0);

        let op_idx = registry.lookup_operator(&id, &OperatorKey::Pov);
        assert_eq!(op_idx, Some(TEST_POV_IDX));
    }

    #[test]
    fn lookup_operator_peer_known() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(0);

        // Get the P2P key of operator 1 from the operator table used to construct the SM
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let p2p_key = table.idx_to_p2p_key(&1).unwrap().clone();

        let op_idx = registry.lookup_operator(&id, &OperatorKey::Peer(&p2p_key.into()));
        assert_eq!(op_idx, Some(1));
    }

    #[test]
    fn lookup_operator_peer_unknown() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(0);

        // A P2P key that doesn't belong to any operator
        let unknown_key = strata_bridge_p2p_types2::P2POperatorPubKey::from(vec![0xFFu8; 33]);
        let op_idx = registry.lookup_operator(&id, &OperatorKey::Peer(&unknown_key));
        assert!(op_idx.is_none());
    }

    #[test]
    fn lookup_operator_missing_sm() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(99);

        let op_idx = registry.lookup_operator(&id, &OperatorKey::Pov);
        assert!(op_idx.is_none());
    }

    // ===== process_event error tests =====

    #[test]
    fn process_event_sm_not_found() {
        let mut registry = test_populated_registry(1);
        let missing_id = SMId::Deposit(99);
        let event = SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
            block_height: 200,
        })));

        let result = registry.process_event(&missing_id, event);
        assert!(matches!(result, Err(ProcessError::SMNotFound(_))));
    }

    #[test]
    fn process_event_type_mismatch() {
        let mut registry = test_populated_registry(1);

        // Send a graph event to a deposit SM ID → InvalidInvocation
        let deposit_id = SMId::Deposit(0);
        let graph_event = SMEvent::Graph(Box::new(GraphEvent::NewBlock(GraphNewBlock {
            block_height: 200,
        })));

        let result = registry.process_event(&deposit_id, graph_event);
        assert!(matches!(result, Err(ProcessError::InvalidInvocation(_, _))));
    }
}
