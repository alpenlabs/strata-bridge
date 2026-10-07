//! Unified types for state machine identity, operator resolution, events, and processing output.

use std::fmt::Display;

use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx, P2POperatorPubKey};
use strata_bridge_sm::{
    deposit::{duties::DepositDuty, events::DepositEvent},
    graph::{duties::GraphDuty, events::GraphEvent},
    stake::{duties::StakeDuty, events::StakeEvent},
};

/// The unique identifier for a state machine in `strata-bridge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SMId {
    /// IDs the state machine responsible for processing a deposit with the given index.
    Deposit(DepositIdx),
    /// IDs the state machine responsible for processing a graph with the given index.
    Graph(GraphIdx),
    /// IDs the state machine responsible for tracking the stake of the operator with the given
    /// index.
    Stake(OperatorIdx),
}

// Note: `DepositIdx` and `OperatorIdx` are both type aliases for `u32`, so a blanket
// `From<u32>` impl would silently dispatch either index to a single `SMId` variant (a
// footgun when constructing stake- or deposit-scoped ids). Use explicit
// `SMId::Deposit(_)` / `SMId::Stake(_)` at the call site instead.

impl From<GraphIdx> for SMId {
    fn from(graph_idx: GraphIdx) -> Self {
        SMId::Graph(graph_idx)
    }
}

impl Display for SMId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SMId::Deposit(deposit_idx) => write!(f, "Deposit({})", deposit_idx),
            SMId::Graph(graph_idx) => write!(
                f,
                "Graph(deposit: {}, operator: {})",
                graph_idx.deposit, graph_idx.operator
            ),
            SMId::Stake(operator_idx) => write!(f, "Stake(operator: {})", operator_idx),
        }
    }
}

/// Identifies which operator to resolve from a state machine's operator table.
#[derive(Debug)]
pub enum OperatorKey<'a> {
    /// Our own operator (point-of-view).
    Pov,
    /// An operator identified by their peer P2P public key.
    Peer(&'a P2POperatorPubKey),
}

/// Wrapper for state-machine-specific events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SMEvent {
    /// An event related to the deposit state machine.
    Deposit(Box<DepositEvent>),
    /// An event related to the graph state machine.
    Graph(Box<GraphEvent>),
    /// An event related to the stake state machine.
    Stake(Box<StakeEvent>),
}

impl Display for SMEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SMEvent::Deposit(event) => write!(f, "DepositEvent({event})"),
            SMEvent::Graph(event) => write!(f, "GraphEvent({event})"),
            SMEvent::Stake(event) => write!(f, "StakeEvent({event})"),
        }
    }
}

impl From<DepositEvent> for SMEvent {
    fn from(event: DepositEvent) -> Self {
        SMEvent::Deposit(Box::new(event))
    }
}

impl From<GraphEvent> for SMEvent {
    fn from(event: GraphEvent) -> Self {
        SMEvent::Graph(Box::new(event))
    }
}

impl From<StakeEvent> for SMEvent {
    fn from(event: StakeEvent) -> Self {
        SMEvent::Stake(Box::new(event))
    }
}

/// A wrapper for holding all the different types of duties that a state machine can emit after a
/// successful STF.
#[derive(Debug, Clone)]
#[expect(clippy::large_enum_variant)]
pub enum UnifiedDuty {
    /// A duty related to a deposit.
    Deposit(DepositDuty),
    /// A duty related to the game graph.
    Graph(GraphDuty),
    /// A duty related to an operator's stake.
    Stake(StakeDuty),
}

impl UnifiedDuty {
    /// Whether to suppress this duty at dispatch while the safe harbour is active: true for the
    /// duties that front a user or advance a claim/payout towards spending the deposit UTXO. See
    /// [`DepositDuty::should_suppress_under_safe_harbour`] and
    /// [`GraphDuty::should_suppress_under_safe_harbour`].
    pub const fn should_suppress_under_safe_harbour(&self) -> bool {
        match self {
            UnifiedDuty::Deposit(duty) => duty.should_suppress_under_safe_harbour(),
            UnifiedDuty::Graph(duty) => duty.should_suppress_under_safe_harbour(),
            UnifiedDuty::Stake(_) => false,
        }
    }
}

impl Display for UnifiedDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deposit(duty) => Display::fmt(duty, f),
            Self::Graph(duty) => Display::fmt(duty, f),
            Self::Stake(duty) => Display::fmt(duty, f),
        }
    }
}

impl From<DepositDuty> for UnifiedDuty {
    fn from(duty: DepositDuty) -> Self {
        UnifiedDuty::Deposit(duty)
    }
}
impl From<GraphDuty> for UnifiedDuty {
    fn from(duty: GraphDuty) -> Self {
        UnifiedDuty::Graph(duty)
    }
}
impl From<StakeDuty> for UnifiedDuty {
    fn from(duty: StakeDuty) -> Self {
        UnifiedDuty::Stake(duty)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Transaction, absolute, transaction};

    use super::*;

    fn dummy_tx() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    /// The wrapper delegates to the per-domain taxonomies (pinned in bridge-sm's duty tests);
    /// stake duties are never suppressed.
    #[test]
    fn should_suppress_under_safe_harbour_delegates_per_domain() {
        use strata_bridge_test_utils::bridge_fixtures::random_p2tr_desc;

        let fulfill: UnifiedDuty = DepositDuty::FulfillWithdrawalRequest {
            deposit_idx: 0,
            deadline: 100,
            recipient_desc: random_p2tr_desc(),
            deposit_amount: Amount::from_sat(1_000_000),
        }
        .into();
        assert!(fulfill.should_suppress_under_safe_harbour());

        let payout: UnifiedDuty = GraphDuty::PublishUncontestedPayout {
            signed_uncontested_payout_tx: dummy_tx(),
        }
        .into();
        assert!(payout.should_suppress_under_safe_harbour());

        let slash: UnifiedDuty = GraphDuty::PublishSlash {
            signed_slash_tx: dummy_tx(),
        }
        .into();
        assert!(
            !slash.should_suppress_under_safe_harbour(),
            "defensive duties are never suppressed"
        );

        let stake: UnifiedDuty = StakeDuty::PublishStakeData { operator_idx: 0 }.into();
        assert!(!stake.should_suppress_under_safe_harbour());
    }
}
