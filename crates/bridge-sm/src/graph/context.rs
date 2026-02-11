//! Context for the Graph State Machine.

use strata_bridge_primitives::types::OperatorIdx;

/// Execution context for a single instance of the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GraphSMCtx {
    /// The index of the deposit this graph is associated with.
    pub deposit_idx: u32,

    /// The index of the operator this graph belongs to.
    pub operator_idx: OperatorIdx,

    /// The output UTXO of the deposit transaction being tracked in a Graph State
    /// Machine.
    pub deposit_outpoint: OutPoint,
}
