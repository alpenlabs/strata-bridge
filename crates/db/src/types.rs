//! Database types that are agnostic to the underlying database implementation.

use bitcoin::{Transaction, TxOut};
use strata_asm_bridge_types::SafeHarbourAddress;
use strata_bridge_primitives::{
    covenant::StakeKey,
    types::{DepositIdx, GraphIdx},
};
use strata_bridge_sm::{
    deposit::machine::DepositSM, graph::machine::GraphSM, operator_set::OperatorSetSM,
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

/// State read at a single database version for registry recovery.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PersistedState {
    /// Deposit rows, including their durable identities.
    pub deposits: Vec<(DepositIdx, DepositSM)>,
    /// Graph rows, including their durable identities.
    pub graphs: Vec<(GraphIdx, GraphSM)>,
    /// Historical and current stake rows, including their durable identities.
    pub stakes: Vec<(StakeKey, StakeSM)>,
    /// Public membership and its complete transition history.
    pub operator_set: Option<OperatorSetSM>,
    /// The frozen safe-harbour destination, if latched.
    pub safe_harbour: Option<SafeHarbourAddress>,
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
    /// Stake state machines to persist, keyed by covenant and operator index.
    stakes: Vec<StakeSM>,
    operator_set: Option<OperatorSetSM>,
}

impl WriteBatch {
    /// Creates a new, empty `WriteBatch`.
    pub const fn new() -> Self {
        Self {
            deposits: Vec::new(),
            graphs: Vec::new(),
            stakes: Vec::new(),
            operator_set: None,
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

    /// Returns the membership state included in this transaction.
    pub const fn operator_set(&self) -> Option<&OperatorSetSM> {
        self.operator_set.as_ref()
    }

    /// Includes the membership state in this transaction.
    pub fn set_operator_set(&mut self, operator_set: OperatorSetSM) {
        self.operator_set = Some(operator_set);
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
}
