//! Database types that are agnostic to the underlying database implementation.

use bitcoin::{Transaction, TxOut};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx};
use strata_bridge_sm::{
    deposit::{config::DepositSMCfg, machine::DepositSM},
    graph::{config::GraphSMCfg, machine::GraphSM},
    stake::machine::StakeSM,
};

/// A persisted plan for an operator's stake funding transaction.
///
/// Pins the unsigned transaction and its prevouts so the same txid and signatures can be
/// reproduced without re-running input selection or fee estimation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeFundingReservation {
    /// The unsigned funding transaction.
    pub unsigned_tx: Transaction,

    /// The prevouts for the inputs of `unsigned_tx`, in input order.
    pub prevouts: Vec<TxOut>,

    /// Index of the reserved-wallet funding output in `unsigned_tx.output`.
    pub stake_output_vout: u32,
}

/// Result of claiming a first-writer-wins funding assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingAssignment<T> {
    /// The caller created the assignment with the supplied value.
    Created(T),
    /// The assignment already existed and this value is the durable assignment.
    Existing(T),
}

impl<T> FundingAssignment<T> {
    /// Returns the assigned value, regardless of whether it was created or already existed.
    pub fn into_inner(self) -> T {
        match self {
            Self::Created(value) | Self::Existing(value) => value,
        }
    }

    /// Returns a reference to the assigned value.
    pub const fn as_ref(&self) -> &T {
        match self {
            Self::Created(value) | Self::Existing(value) => value,
        }
    }
}

/// A batch of state machine writes to persist atomically.
///
/// This can be used to persist causally-linked state machine updates in a single transaction,
/// ensuring consistency and atomicity. For example, when processing a deposit, you might want to
/// update both the deposit state machine and the associated graph state machines in a single batch.
#[derive(Debug, Default, Clone)]
pub struct WriteBatch {
    /// Deposit state machines to persist, keyed by deposit index.
    deposits: Vec<DepositSM>,
    /// Graph state machines to persist, keyed by graph index.
    graphs: Vec<GraphSM>,
    /// Stake state machines to persist, keyed by operator index.
    stakes: Vec<StakeSM>,
    /// Params of the deposits to persist, keyed by deposit index.
    deposit_params: Vec<(DepositIdx, DepositSMCfg)>,
    /// Params of the graphs to persist, keyed by graph index.
    graph_params: Vec<(GraphIdx, GraphSMCfg)>,
}

impl WriteBatch {
    /// Creates a new, empty `WriteBatch`.
    pub const fn new() -> Self {
        Self {
            deposits: Vec::new(),
            graphs: Vec::new(),
            stakes: Vec::new(),
            deposit_params: Vec::new(),
            graph_params: Vec::new(),
        }
    }

    /// Returns the deposit state machines in the batch.
    pub fn deposits(&self) -> &[DepositSM] {
        &self.deposits
    }

    /// Returns the graph state machines in the batch.
    pub fn graphs(&self) -> &[GraphSM] {
        &self.graphs
    }

    /// Returns the stake state machines in the batch.
    pub fn stakes(&self) -> &[StakeSM] {
        &self.stakes
    }

    /// Returns the deposit params in the batch.
    pub fn deposit_params(&self) -> &[(DepositIdx, DepositSMCfg)] {
        &self.deposit_params
    }

    /// Returns the graph params in the batch.
    pub fn graph_params(&self) -> &[(GraphIdx, GraphSMCfg)] {
        &self.graph_params
    }

    /// Adds a deposit state machine to the batch.
    pub fn add_deposit(&mut self, deposit_sm: DepositSM) {
        self.deposits.push(deposit_sm);
    }

    /// Adds a graph state machine to the batch.
    pub fn add_graph(&mut self, graph_sm: GraphSM) {
        self.graphs.push(graph_sm);
    }

    /// Adds a stake state machine to the batch.
    pub fn add_stake(&mut self, stake_sm: StakeSM) {
        self.stakes.push(stake_sm);
    }

    /// Adds the params of a deposit to the batch.
    pub fn add_deposit_params(&mut self, deposit_idx: DepositIdx, cfg: DepositSMCfg) {
        self.deposit_params.push((deposit_idx, cfg));
    }

    /// Adds the params of a graph to the batch.
    pub fn add_graph_params(&mut self, graph_idx: GraphIdx, cfg: GraphSMCfg) {
        self.graph_params.push((graph_idx, cfg));
    }
}
