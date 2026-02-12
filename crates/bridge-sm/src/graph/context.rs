//! Context for the Graph State Machine.

use bitcoin::OutPoint;
use strata_bridge_primitives::types::OperatorIdx;

/// Execution context for a single instance of the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GraphSMCtx {
    /// The index of the deposit this graph is associated with.
    pub deposit_idx: u32,

    /// The index of the operator this graph belongs to.
    pub operator_idx: OperatorIdx,

    /// The deposit UTXO this graph is associated with.
    pub deposit_outpoint: OutPoint,
}
