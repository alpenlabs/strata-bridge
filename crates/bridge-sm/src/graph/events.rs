//! The events that are relevant to the Graph State Machine.
//!
//! Depending upon the exact state that the state machine is in, these events will trigger
//! different transitions and emit duties that need to be performed and messages that need to be
//! propagated.

use std::fmt::Display;

use bitcoin::{Txid, taproot::Signature};
use bitcoin_bosd::Descriptor;
use musig2::PubNonce;
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};
use strata_bridge_tx_graph2::game_graph::GameGraph;
use zkaleido::ProofReceipt;

/// Event notifying that graph data has been generated for a graph instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphDataGeneratedEvent {
    /// The generated pegout graph data.
    pub graph_data: GameGraph,
}

/// Event notifying that all adaptors for the graph have been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorsVerifiedEvent {}

/// Event notifying that a nonce bundle for the graph has been received from an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNonceReceivedEvent {
    /// The index of the operator who sent the nonce.
    pub operator_idx: OperatorIdx,

    /// The public nonce from this operator.
    pub nonce: PubNonce,
}

/// Event notifying that a partial-signature bundle for the graph has been received from an
/// operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPartialReceivedEvent {
    /// The index of the operator who sent the partial signature.
    pub operator_idx: OperatorIdx,

    /// The partial signature from this operator.
    pub partial_sig: Signature,
}

/// Event notifying that a withdrawal has been assigned/reassigned (for this graph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalAssignedEvent {
    /// The operator assigned to fulfill the withdrawal.
    pub assignee: OperatorIdx,

    /// The block height deadline for the assignment.
    pub deadline: BitcoinBlockHeight,

    /// The descriptor of the withdrawal recipient.
    pub recipient_desc: Descriptor,
}

/// Event notifying that the fulfillment transaction has been confirmed on-chain (for this graph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentConfirmedEvent {
    /// The txid of the fulfillment transaction.
    pub fulfillment_txid: Txid,

    /// The block height at which the fulfillment transaction was confirmed.
    pub fulfillment_block_height: BitcoinBlockHeight,
}

/// Event notifying that a claim transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimConfirmedEvent {
    /// The txid of the confirmed claim transaction.
    pub claim_txid: Txid,

    /// The block height at which the claim transaction was confirmed.
    pub claim_block_height: BitcoinBlockHeight,
}

/// Event notifying that a contest transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContestConfirmedEvent {
    /// The txid of the confirmed contest transaction.
    pub contest_txid: Txid,

    /// The block height at which the contest transaction was confirmed.
    pub contest_block_height: BitcoinBlockHeight,
}

/// Event notifying that a bridge proof transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeProofConfirmedEvent {
    /// The txid of the bridge proof transaction.
    pub bridge_proof_txid: Txid,

    /// The block height at which the bridge proof transaction was confirmed.
    pub bridge_proof_block_height: BitcoinBlockHeight,

    /// The bridge proof.
    pub proof: ProofReceipt,
}

/// Event notifying that a bridge proof timeout transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeProofTimeoutConfirmedEvent {
    /// The txid of the bridge proof timeout transaction.
    pub bridge_proof_timeout_txid: Txid,

    /// The block height at which the bridge proof timeout transaction was confirmed.
    pub bridge_proof_timeout_block_height: BitcoinBlockHeight,
}

/// Event notifying that a counterproof transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofConfirmedEvent {
    /// The txid of the counterproof transaction.
    pub counterproof_txid: Txid,

    /// The block height at which the counterproof transaction was confirmed.
    pub counterproof_block_height: BitcoinBlockHeight,
}

/// Event notifying that a counterproof ACK transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofAckConfirmedEvent {
    /// The txid of the counterproof ACK transaction.
    pub counterproof_ack_txid: Txid,

    /// The block height at which the counterproof ACK transaction was confirmed.
    pub counterproof_ack_block_height: BitcoinBlockHeight,
}

/// Event notifying that a counterproof NACK transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofNackConfirmedEvent {
    /// The txid of the counterproof NACK transaction.
    pub counterproof_nack_txid: Txid,

    /// The index of the operator whose counterproof is being NACK'd.
    pub nacker_idx: OperatorIdx,
}

/// Event notifying that a slash transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashConfirmedEvent {
    /// The txid of the slash transaction.
    pub slash_txid: Txid,
}

/// Event notifying that a payout transaction (uncontested or contested) has been confirmed
/// on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutConfirmedEvent {
    /// The txid of the payout transaction.
    pub payout_txid: Txid,
}

/// Event signifying that the payout connector was spent by some transaction (abort condition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutConnectorSpentEvent {
    /// The txid of the transaction that spent the payout connector.
    pub spending_txid: Txid,
}

/// Event signalling that a new block has been observed on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBlockEvent {
    /// The new block height.
    pub block_height: BitcoinBlockHeight,
}

/// The external events that affect the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphEvent {
    /// Graph data has been generated for the graph instance.
    GraphDataProduced(GraphDataGeneratedEvent),
    /// All adaptors for the graph have been verified.
    AdaptorsVerified(AdaptorsVerifiedEvent),
    /// Nonce bundle for the graph received from an operator.
    NonceReceived(GraphNonceReceivedEvent),
    /// Partial-signature bundle for the graph received from an operator.
    PartialReceived(GraphPartialReceivedEvent),
    /// Withdrawal assigned/reassigned for this graph.
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
    /// Payout transaction (uncontested or contested) confirmed on-chain.
    PayoutConfirmed(PayoutConfirmedEvent),
    /// Payout connector spent by some transaction (abort condition).
    PayoutConnectorSpent(PayoutConnectorSpentEvent),
    /// New block observed on chain.
    ///
    /// This is required to deal with timelocks in various states and to track the last observed
    /// block.
    NewBlock(NewBlockEvent),
}

impl From<GraphNonceReceivedEvent> for GraphEvent {
    fn from(event: GraphNonceReceivedEvent) -> Self {
        GraphEvent::NonceReceived(event)
    }
}

impl From<AdaptorsVerifiedEvent> for GraphEvent {
    fn from(event: AdaptorsVerifiedEvent) -> Self {
        GraphEvent::AdaptorsVerified(event)
    }
}

impl From<GraphDataGeneratedEvent> for GraphEvent {
    fn from(event: GraphDataGeneratedEvent) -> Self {
        GraphEvent::GraphDataProduced(event)
    }
}

impl From<GraphPartialReceivedEvent> for GraphEvent {
    fn from(event: GraphPartialReceivedEvent) -> Self {
        GraphEvent::PartialReceived(event)
    }
}

impl From<WithdrawalAssignedEvent> for GraphEvent {
    fn from(event: WithdrawalAssignedEvent) -> Self {
        GraphEvent::WithdrawalAssigned(event)
    }
}

impl From<ClaimConfirmedEvent> for GraphEvent {
    fn from(event: ClaimConfirmedEvent) -> Self {
        GraphEvent::ClaimConfirmed(event)
    }
}

impl From<ContestConfirmedEvent> for GraphEvent {
    fn from(event: ContestConfirmedEvent) -> Self {
        GraphEvent::ContestConfirmed(event)
    }
}

impl From<FulfillmentConfirmedEvent> for GraphEvent {
    fn from(event: FulfillmentConfirmedEvent) -> Self {
        GraphEvent::FulfillmentConfirmed(event)
    }
}

impl From<BridgeProofConfirmedEvent> for GraphEvent {
    fn from(event: BridgeProofConfirmedEvent) -> Self {
        GraphEvent::BridgeProofConfirmed(event)
    }
}

impl From<BridgeProofTimeoutConfirmedEvent> for GraphEvent {
    fn from(event: BridgeProofTimeoutConfirmedEvent) -> Self {
        GraphEvent::BridgeProofTimeoutConfirmed(event)
    }
}

impl From<CounterProofConfirmedEvent> for GraphEvent {
    fn from(event: CounterProofConfirmedEvent) -> Self {
        GraphEvent::CounterProofConfirmed(event)
    }
}

impl From<CounterProofAckConfirmedEvent> for GraphEvent {
    fn from(event: CounterProofAckConfirmedEvent) -> Self {
        GraphEvent::CounterProofAckConfirmed(event)
    }
}

impl From<CounterProofNackConfirmedEvent> for GraphEvent {
    fn from(event: CounterProofNackConfirmedEvent) -> Self {
        GraphEvent::CounterProofNackConfirmed(event)
    }
}

impl From<SlashConfirmedEvent> for GraphEvent {
    fn from(event: SlashConfirmedEvent) -> Self {
        GraphEvent::SlashConfirmed(event)
    }
}

impl From<PayoutConfirmedEvent> for GraphEvent {
    fn from(event: PayoutConfirmedEvent) -> Self {
        GraphEvent::PayoutConfirmed(event)
    }
}

impl From<PayoutConnectorSpentEvent> for GraphEvent {
    fn from(event: PayoutConnectorSpentEvent) -> Self {
        GraphEvent::PayoutConnectorSpent(event)
    }
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
