//! The events that are relevant to the Graph State Machine.
//!
//! Depending upon the exact state that the state machine is in, these events will trigger
//! different transitions and emit duties that need to be performed and messages that need to be
//! propagated.

use std::fmt::Display;

/// Event notifying that graph data has been generated for a graph instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphDataProducedEvent {}

/// Event notifying that all adaptors for the graph have been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorsVerifiedEvent {}

/// Event notifying that a nonce bundle for the graph has been received from an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNonceReceivedEvent {}

/// Event notifying that a partial-signature bundle for the graph has been received from an
/// operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPartialReceivedEvent {}

/// Event notifying that a withdrawal has been assigned/reassigned (for this graph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalAssignedEvent {}

/// Event notifying that the fulfillment transaction has been confirmed on-chain (for this graph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentConfirmedEvent {}

/// Event notifying that a claim transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimConfirmedEvent {}

/// Event notifying that a contest transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContestConfirmedEvent {}

/// Event notifying that a bridge proof transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeProofConfirmedEvent {}

/// Event notifying that a bridge proof timeout transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeProofTimeoutConfirmedEvent {}

/// Event notifying that a counterproof transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofConfirmedEvent {}

/// Event notifying that a counterproof ACK transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofAckConfirmedEvent {}

/// Event notifying that a counterproof NACK transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofNackConfirmedEvent {}

/// Event notifying that a slash transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashConfirmedEvent {}

/// Event notifying that a payout transaction (uncontested or contested) has been confirmed
/// on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutConfirmedEvent {}

/// Event signifying that the payout connector was spent by some transaction (abort condition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutConnectorSpentEvent {}

/// Event signalling that a new block has been observed on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBlockEvent {}

/// The external events that affect the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphEvent {
    /// Graph data has been generated for this graph instance.
    GraphDataProduced(GraphDataProducedEvent),
    /// All adaptors for the generated graph have been verified.
    AdaptorsVerified(AdaptorsVerifiedEvent),
    /// Nonce bundle received from an operator for graph signing.
    NonceReceived(GraphNonceReceivedEvent),
    /// Partial signature bundle received from an operator for graph signing.
    PartialReceived(GraphPartialReceivedEvent),
    /// Withdrawal assignment / reassignment for this graph.
    WithdrawalAssigned(WithdrawalAssignedEvent),
    /// Fulfillment transaction confirmed on-chain.
    FulfillmentConfirmed(FulfillmentConfirmedEvent),
    /// Claim transaction confirmed on-chain.
    ClaimConfirmed(ClaimConfirmedEvent),
    /// Contest transaction confirmed on-chain.
    ContestConfirmed(ContestConfirmedEvent),
    /// Bridge proof transaction confirmed on-chain.
    BridgeProofConfirmed(BridgeProofConfirmedEvent),
    /// Bridge proof timeout transaction confirmed on-chain.
    BridgeProofTimeoutConfirmed(BridgeProofTimeoutConfirmedEvent),
    /// Counterproof transaction confirmed on-chain.
    CounterProofConfirmed(CounterProofConfirmedEvent),
    /// Counterproof ACK transaction confirmed on-chain.
    CounterProofAckConfirmed(CounterProofAckConfirmedEvent),
    /// Counterproof NACK transaction confirmed on-chain.
    CounterProofNackConfirmed(CounterProofNackConfirmedEvent),
    /// Slash transaction confirmed on-chain.
    SlashConfirmed(SlashConfirmedEvent),
    /// Payout transaction confirmed on-chain (uncontested or contested).
    PayoutConfirmed(PayoutConfirmedEvent),
    /// Payout connector spent observed (abort condition).
    PayoutConnectorSpent(PayoutConnectorSpentEvent),
    /// Event signalling that a new block has been observed on chain.
    ///
    /// This is required to deal with timelocks in various states and to track the last observed
    /// block.
    NewBlock(NewBlockEvent),
}

impl Display for GraphEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            GraphEvent::GraphDataProduced(_) => "GraphDataProduced",
            GraphEvent::AdaptorsVerified(_) => "AdaptorsVerified",
            GraphEvent::NonceReceived(_) => "NonceReceived",
            GraphEvent::PartialReceived(_) => "PartialReceived",
            GraphEvent::WithdrawalAssigned(_) => "WithdrawalAssigned",
            GraphEvent::FulfillmentConfirmed(_) => "FulfillmentConfirmed",
            GraphEvent::ClaimConfirmed(_) => "ClaimConfirmed",
            GraphEvent::ContestConfirmed(_) => "ContestConfirmed",
            GraphEvent::BridgeProofConfirmed(_) => "BridgeProofConfirmed",
            GraphEvent::BridgeProofTimeoutConfirmed(_) => "BridgeProofTimeoutConfirmed",
            GraphEvent::CounterProofConfirmed(_) => "CounterProofConfirmed",
            GraphEvent::CounterProofAckConfirmed(_) => "CounterProofAckConfirmed",
            GraphEvent::CounterProofNackConfirmed(_) => "CounterProofNackConfirmed",
            GraphEvent::SlashConfirmed(_) => "SlashConfirmed",
            GraphEvent::PayoutConfirmed(_) => "PayoutConfirmed",
            GraphEvent::PayoutConnectorSpent(_) => "PayoutConnectorSpent",
            GraphEvent::NewBlock(_) => "NewBlock",
        };
        write!(f, "{}", display_str)
    }
}
