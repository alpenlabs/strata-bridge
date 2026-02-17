//! Database types that are agnostic to the underlying database implementation.

use strata_bridge_sm::{deposit::machine::DepositSM, graph::machine::GraphSM};

/// Which transaction the stored outpoints fund.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FundingPurpose {
    /// Operator-controlled UTXOs that fund the withdrawal fulfillment tx.
    WithdrawalFulfillment = 0,
    /// UTXO that funds the claim tx (typically a single outpoint).
    Claim = 1,
}

impl FundingPurpose {
    /// Converts from a `u8` discriminant.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::WithdrawalFulfillment),
            1 => Some(Self::Claim),
            _ => None,
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
}

impl WriteBatch {
    /// Creates a new, empty `WriteBatch`.
    pub const fn new() -> Self {
        Self {
            deposits: Vec::new(),
            graphs: Vec::new(),
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

    /// Adds a deposit state machine to the batch.
    pub fn add_deposit(&mut self, deposit_sm: DepositSM) {
        self.deposits.push(deposit_sm);
    }

    /// Adds a graph state machine to the batch.
    pub fn add_graph(&mut self, graph_sm: GraphSM) {
        self.graphs.push(graph_sm);
    }
}
