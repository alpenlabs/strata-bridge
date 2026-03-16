//! The events that are relevant to the Graph State Machine.
//!
//! Depending upon the exact state that the state machine is in, these events will trigger
//! different transitions and emit duties that need to be performed and messages that need to be
//! propagated.

use std::fmt::Display;

use bitcoin::{OutPoint, Txid};
use bitcoin_bosd::Descriptor;
use musig2::{PartialSignature, PubNonce};
use strata_bridge_p2p_types::NagRequestPayload;
use strata_bridge_primitives::types::{BitcoinBlockHeight, GraphIdx, OperatorIdx};
use zkaleido::ProofReceipt;

use crate::signals::DepositToGraph;

/// Event notifying that graph data has been generated for a graph instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphDataGeneratedEvent {
    /// The index of the graph this event is for.
    pub graph_idx: GraphIdx,
    /// UTXO that funds the claim transaction.
    pub claim_funds: OutPoint,
}

/// Event notifying that all adaptors for the graph have been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptorsVerifiedEvent {}

/// Event notifying that a nonce bundle for the graph has been received from an operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNoncesReceivedEvent {
    /// The index of the operator who sent the nonce.
    pub operator_idx: OperatorIdx,

    /// The public nonces from this operator.
    pub pubnonces: Vec<PubNonce>,
}

/// Event notifying that a partial-signature bundle for the graph has been received from an
/// operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPartialsReceivedEvent {
    /// The index of the operator who sent the partial signature.
    pub operator_idx: OperatorIdx,

    /// The partial signatures from this operator.
    pub partial_signatures: Vec<PartialSignature>,
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

    /// The index of the watchtower who submitted the counterproof transaction.
    pub counterprover_idx: OperatorIdx,
}

/// Event notifying that a counterproof ACK transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofAckConfirmedEvent {
    /// The txid of the counterproof ACK transaction.
    pub counterproof_ack_txid: Txid,

    /// The block height at which the counterproof ACK transaction was confirmed.
    pub counterproof_ack_block_height: BitcoinBlockHeight,

    /// The index of the watchtower who submitted the corresponding counterproof transaction.
    pub counterprover_idx: OperatorIdx,
}

/// Event notifying that a counterproof NACK transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterProofNackConfirmedEvent {
    /// The txid of the counterproof NACK transaction.
    pub counterproof_nack_txid: Txid,

    /// The index of the watchtower who submitted the corresponding counterproof transaction.
    pub counterprover_idx: OperatorIdx,
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

/// Event signalling that retriable duties should be emitted again for the current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryTickEvent;

/// Event signalling that nag duties should be emitted for missing operator data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NagTickEvent;

/// Event received when another operator nags for missing graph data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NagReceivedEvent {
    /// The nag payload describing what's being requested.
    pub payload: NagRequestPayload,
    /// The operator index of the sender.
    pub sender_operator_idx: OperatorIdx,
}

/// The external events that affect the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphEvent {
    /// Graph data has been generated for the graph instance.
    GraphDataProduced(GraphDataGeneratedEvent),
    /// Message received from the Deposit State Machine.
    DepositMessage(DepositToGraph),
    /// All adaptors for the graph have been verified.
    AdaptorsVerified(AdaptorsVerifiedEvent),
    /// Nonce bundle for the graph received from an operator.
    NoncesReceived(GraphNoncesReceivedEvent),
    /// Partial-signature bundle for the graph received from an operator.
    PartialsReceived(GraphPartialsReceivedEvent),
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
    /// Event signalling that retriable duties should be emitted again for the current state.
    RetryTick(RetryTickEvent),
    /// Event signalling that nag duties should be emitted for missing operator data.
    NagTick(NagTickEvent),
    /// Event received when another operator nags for missing graph data.
    NagReceived(NagReceivedEvent),
}

impl Display for GraphEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            GraphEvent::GraphDataProduced(_) => "GraphDataProduced",
            GraphEvent::DepositMessage(_) => "DepositMessage",
            GraphEvent::AdaptorsVerified(_) => "AdaptorsVerified",
            GraphEvent::NoncesReceived(_) => "NonceReceived",
            GraphEvent::PartialsReceived(_) => "PartialReceived",
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
            GraphEvent::RetryTick(_) => "RetryTick",
            GraphEvent::NagTick(_) => "NagTick",
            GraphEvent::NagReceived(_) => "NagReceived",
        };
        write!(f, "{}", display_str)
    }
}

/// Implements `From<T> for GraphEvent` for leaf event types.
///
/// This allows all graph-related event structs to be ergonomically
/// converted into `GraphEvent` via `.into()` and used uniformly
/// by the Graph State Machine.
macro_rules! impl_into_graph_event {
    ($t:ty, $variant:ident) => {
        impl From<$t> for GraphEvent {
            fn from(e: $t) -> Self {
                GraphEvent::$variant(e)
            }
        }
    };
}

impl_into_graph_event!(GraphDataGeneratedEvent, GraphDataProduced);
impl_into_graph_event!(DepositToGraph, DepositMessage);
impl_into_graph_event!(AdaptorsVerifiedEvent, AdaptorsVerified);
impl_into_graph_event!(GraphNoncesReceivedEvent, NoncesReceived);
impl_into_graph_event!(GraphPartialsReceivedEvent, PartialsReceived);
impl_into_graph_event!(WithdrawalAssignedEvent, WithdrawalAssigned);
impl_into_graph_event!(FulfillmentConfirmedEvent, FulfillmentConfirmed);
impl_into_graph_event!(ClaimConfirmedEvent, ClaimConfirmed);
impl_into_graph_event!(ContestConfirmedEvent, ContestConfirmed);
impl_into_graph_event!(BridgeProofConfirmedEvent, BridgeProofConfirmed);
impl_into_graph_event!(
    BridgeProofTimeoutConfirmedEvent,
    BridgeProofTimeoutConfirmed
);
impl_into_graph_event!(CounterProofConfirmedEvent, CounterProofConfirmed);
impl_into_graph_event!(CounterProofAckConfirmedEvent, CounterProofAckConfirmed);
impl_into_graph_event!(CounterProofNackConfirmedEvent, CounterProofNackConfirmed);
impl_into_graph_event!(SlashConfirmedEvent, SlashConfirmed);
impl_into_graph_event!(PayoutConfirmedEvent, PayoutConfirmed);
impl_into_graph_event!(PayoutConnectorSpentEvent, PayoutConnectorSpent);
impl_into_graph_event!(NewBlockEvent, NewBlock);
impl_into_graph_event!(RetryTickEvent, RetryTick);
impl_into_graph_event!(NagTickEvent, NagTick);
impl_into_graph_event!(NagReceivedEvent, NagReceived);
