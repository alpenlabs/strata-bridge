//! Context for the Stake State Machine.

use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};

/// Execution context for a single instance of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeSMCtx {
    // Invariant: `operator_idx` is included in `operator_table`.
    /// The index of the operator whose stake is tracked by this state machine.
    operator_idx: OperatorIdx,

    /// The operator table for this state machine instance.
    operator_table: OperatorTable,
}

impl StakeSMCtx {
    /// Creates a new Stake State Machine context.
    ///
    /// # Panics
    ///
    /// This method panics if the operator index is not included in the operator table.
    pub fn new(operator_idx: OperatorIdx, operator_table: OperatorTable) -> Self {
        assert!(
            operator_table.contains_idx(&operator_idx),
            "The operator index must be included in the operator table"
        );

        Self {
            operator_idx,
            operator_table,
        }
    }

    /// Returns the index of the operator whose stake is tracked.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.operator_idx
    }

    /// Returns the operator table.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }
}
