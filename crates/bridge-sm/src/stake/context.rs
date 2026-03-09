//! Context for the Stake State Machine.

use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};

/// Execution context for a single instance of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeSMCtx {
    /// The index of the operator whose stake is tracked by this state machine.
    pub operator_idx: OperatorIdx,

    /// The operator table for this state machine instance.
    pub operator_table: OperatorTable,
}

impl StakeSMCtx {
    /// Returns the index of the operator whose stake is tracked.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.operator_idx
    }

    /// Returns the operator table.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }
}
