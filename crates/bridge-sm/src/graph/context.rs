//! Context for the Graph State Machine.

use bitcoin::OutPoint;
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};

/// Execution context for a single instance of the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GraphSMCtx {
    /// The index of the deposit this graph is associated with.
    pub deposit_idx: u32,

    /// The index of the operator this graph belongs to.
    pub operator_idx: OperatorIdx,

    /// The deposit UTXO this graph is associated with.
    pub deposit_outpoint: OutPoint,

    /// The operator table for the graph state machine instance.
    pub operator_table: OperatorTable,
}

impl GraphSMCtx {
    /// Returns the index of the deposit this graph is associated with.
    pub const fn deposit_idx(&self) -> u32 {
        self.deposit_idx
    }

    /// Returns the index of the operator this graph belongs to.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.operator_idx
    }

    /// Returns the deposit UTXO this graph is associated with.
    pub const fn deposit_outpoint(&self) -> OutPoint {
        self.deposit_outpoint
    }

    /// Returns the operator table for the graph state machine instance.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }
}
