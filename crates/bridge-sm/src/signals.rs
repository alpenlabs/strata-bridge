//! Messages that need to be transferred between different state machines in the bridge.

use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

/// The signals that need to be sent across different state machines in the bridge.
///
/// This is a sum of directional contracts between different state machines. Each variant represents
/// a distinct wire protocol between two state machines.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Signal {
    /// Messages from the Deposit State Machine.
    FromDeposit(DepositSignal),

    /// Messages from the Graph State Machine.
    FromGraph(GraphSignal),
}

/// Signals that the [Deposit State Machine](crate::deposit::machine::DepositSM) can emit.
///
/// This enum is type-safe: it only contains signals that the Deposit SM is allowed to produce.
/// Each variant represents a different destination state machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositSignal {
    /// Signal to the Graph State Machine.
    ToGraph(DepositToGraph),
    // Future: Add other destinations as needed
}

impl From<DepositSignal> for Signal {
    fn from(sig: DepositSignal) -> Self {
        Signal::FromDeposit(sig)
    }
}

/// Signals that the Graph State Machine can emit.
///
/// This enum is type-safe: it only contains signals that the Graph SM is allowed to produce.
/// Each variant represents a different destination state machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GraphSignal {
    /// Signal to the Deposit State Machine.
    ToDeposit(GraphToDeposit),
    // Future: Add ToOperator(DepositToOperator), etc.
}

impl From<GraphSignal> for Signal {
    fn from(sig: GraphSignal) -> Self {
        Signal::FromGraph(sig)
    }
}

/// The signals that need to be sent from the [Deposit State
/// Machine](crate::deposit::machine::DepositSM) to the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositToGraph {
    /// Indicates that the cooperative payout has failed and so the unilateral withdrawal path has
    /// to be taken.
    CooperativePayoutFailed {
        /// The index of the operator that was assigned.
        assignee: OperatorIdx,
        /// The index of the deposit for which the cooperative payout failed.
        deposit_idx: u32,
        // add more fields if necessary
    },
}

/// The signals that need to be sent from the Graph State Machine to the [Deposit State
/// Machine](crate::deposit::machine::DepositSM).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GraphToDeposit {
    /// Indicates that the pegout graph has been generated and signed.
    GraphAvailable {
        /// The index of the operator for whom the graph is available.
        operator_idx: OperatorIdx,
        /// The index of the deposit for which the graph is available. This is needed to route the
        /// signal to the correct deposit state machine.
        deposit_idx: DepositIdx,
    },
}

impl std::fmt::Display for GraphToDeposit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphToDeposit::GraphAvailable {
                operator_idx,
                deposit_idx,
            } => {
                write!(
                    f,
                    "GraphAvailable for operator_idx: {} for deposit: {}",
                    operator_idx, deposit_idx
                )
            }
        }
    }
}
