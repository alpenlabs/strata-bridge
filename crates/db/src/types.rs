//! Database types that are agnostic to the underlying database implementation.

use bitcoin::{Transaction, TxOut};
use strata_bridge_sm::{
    deposit::machine::DepositSM, graph::machine::GraphSM, stake::machine::StakeSM,
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

    /// Index of the stakechain funding output in `unsigned_tx.output`.
    pub stake_output_vout: u32,
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
}

impl WriteBatch {
    /// Creates a new, empty `WriteBatch`.
    pub const fn new() -> Self {
        Self {
            deposits: Vec::new(),
            graphs: Vec::new(),
            stakes: Vec::new(),
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
