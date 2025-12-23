//! Messages that need to be transferred between different state machines in the bridge.

use strata_bridge_primitives::types::OperatorIdx;

/// The signals that need to be sent across different state machines in the bridge.
///
/// This is a sum of directional contracts between different state machines. Each variant represents
/// a distinct wire protocol between two state machines.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Signal {
    /// Messages from the Deposit State Machine to the Graph State Machine.
    DepositToGraph(DepositToGraph),

    /// Messages from the Graph State Machine to the Deposit State Machine.
    GraphToDeposit(GraphToDeposit),
}

/// The messages that need to be sent from the [Deposit State
/// Machine](crate::deposit::state::DepositSM) to the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositToGraph {
    /// Indicates that the cooperative payout has failed and so the unilateral withdrawal path has
    /// to be taken.
    CooperativePayoutFailed {
        /// The index of the operator that was assigned.
        assignee: OperatorIdx,
        // add more fields if necessary
    },
}

/// The messages that need to be sent from the Graph State Machine to the [Deposit State
/// Machine](crate::deposit::state::DepositSM).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GraphToDeposit {
    /// Indicates that the pegout graph has been generated and signed.
    GraphAvailable {
        /// The index of the operator for whom the graph is available.
        operator_idx: OperatorIdx,
        // add more fields if necessary
    },
}
