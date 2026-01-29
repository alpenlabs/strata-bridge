//! The events that are relevant to the Deposit State Machine.
//!
//! Depending upon the exact state that the state machine is in, these events will trigger
//! different transitions and emit duties that need to be performed and messages that need to be
//! propagated.

use bitcoin::Transaction;
use bitcoin_bosd::Descriptor;
use musig2::{PartialSignature, PubNonce};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};

use crate::signals::GraphToDeposit;

/// Event signifying that the output of the deposit request was spent by the user instead of the
/// bridge covenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTakeBackEvent {
    /// The transaction that spends the deposit request.
    pub tx: Transaction,
}

/// Nonce received from an operator for the deposit transaction signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceReceivedEvent {
    /// The public nonce provided by the operator
    pub nonce: PubNonce,
    /// The index of the operator who provided the nonce
    pub operator_idx: OperatorIdx,
}

/// Partial signature received from an operator for the deposit transaction signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialReceivedEvent {
    /// The partial signature provided by the operator
    pub partial_sig: PartialSignature,
    /// The index of the operator who provided the partial signature
    pub operator_idx: OperatorIdx,
}

/// Event notifying that the deposit has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositConfirmedEvent {
    /// The deposit transaction that has been confirmed on-chain.
    pub deposit_transaction: Transaction,
}

/// Event notifying that the withdrawal request has been assigned to some operator for fulfillment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalAssignedEvent {
    /// The index of the operator assigned to serve the withdrawal request.
    pub assignee: OperatorIdx,
    /// The block height until which the assignment is valid.
    pub deadline: BitcoinBlockHeight,
    /// The user's descriptor where funds are to be sent by the operator.
    pub recipient_desc: Descriptor,
}

/// Event notifying that the fulfillment transaction has been confirmed on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FulfillmentConfirmedEvent {
    /// The fulfillment transaction that has been confirmed on-chain
    pub fulfillment_transaction: Transaction,
    /// The block height at which the fulfillment transaction was confirmed.
    pub fulfillment_height: BitcoinBlockHeight,
}

/// Event notifying that the output descriptor of the operator for the cooperative payout has been
/// received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutDescriptorReceivedEvent {
    /// The output descriptor of the operator where the funds for the cooperative payout are to
    /// be received.
    pub operator_desc: Descriptor,
}

/// Event notifying that a pubnonce from some operator for the cooperative payout transaction has
/// been received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutNonceReceivedEvent {
    /// The pubnonce for the cooperative payout transaction that was received.
    pub payout_nonce: PubNonce,
    /// The operator who sent the pubnonce.
    pub operator_idx: OperatorIdx,
}

/// Event notifying that a partial signature from some operator for the cooperative payout
/// transaction has been received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutPartialReceivedEvent {
    /// The partial signature for the cooperative payout transaction that was received.
    pub partial_signature: PartialSignature,
    /// The operator who sent the partial signature.
    pub operator_idx: OperatorIdx,
}

/// Event notifying that the payout has been confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutConfirmedEvent {
    /// The transaction that confirms the payout.
    pub tx: Transaction,
}

/// Event signalling that a new block has been observed on chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBlockEvent {
    /// The new block height.
    pub block_height: BitcoinBlockHeight,
}

/// The external events that affect the Deposit State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositEvent {
    /// Event signifying that the output of the deposit request was spent by the user instead of the
    /// bridge covenant.
    UserTakeBack(UserTakeBackEvent),
    /// Message received from the Graph State Machine.
    GraphMessage(GraphToDeposit),
    /// Nonce received from an operator for the deposit transaction signing
    NonceReceived(NonceReceivedEvent),
    /// Partial signature received from an operator for the deposit transaction signing
    PartialReceived(PartialReceivedEvent),
    /// This event notifies that the deposit has been confirmed on-chain.
    DepositConfirmed(DepositConfirmedEvent),
    /// This event notifies that the withdrawal request has been assigned to some operator for
    /// fulfillment.
    WithdrawalAssigned(WithdrawalAssignedEvent),
    /// This event notifies that the fulfillment transaction has been confirmed on-chain.
    FulfillmentConfirmed(FulfillmentConfirmedEvent),
    /// This event notifies that the output descriptor of the operator for the cooperative payout
    /// has been received.
    PayoutDescriptorReceived(PayoutDescriptorReceivedEvent),
    /// This event notifies that a pubnonce from some operator for the cooperative payout
    /// transaction has been received.
    PayoutNonceReceived(PayoutNonceReceivedEvent),
    /// This event notifies that a partial signature from some operator for the cooperative payout
    /// transaction has been received.
    PayoutPartialReceived(PayoutPartialReceivedEvent),
    /// TODO: (@Rajil1213)
    PayoutConfirmed(PayoutConfirmedEvent),
    /// Event signalling that a new block has been observed on chain.
    ///
    /// This is required to deal with timelocks in various states and to track the last observed
    /// block.
    NewBlock(NewBlockEvent),
}

impl std::fmt::Display for DepositEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DepositEvent::UserTakeBack(event) => write!(f, "{}", event),
            DepositEvent::GraphMessage(graph_msg) => write!(f, "{}", graph_msg),
            DepositEvent::NonceReceived(event) => write!(f, "{}", event),
            DepositEvent::PartialReceived(event) => write!(f, "{}", event),
            DepositEvent::DepositConfirmed(event) => write!(f, "{}", event),
            DepositEvent::WithdrawalAssigned(event) => write!(f, "{}", event),
            DepositEvent::FulfillmentConfirmed(event) => write!(f, "{}", event),
            DepositEvent::PayoutDescriptorReceived(event) => write!(f, "{}", event),
            DepositEvent::PayoutNonceReceived(event) => write!(f, "{}", event),
            DepositEvent::PayoutPartialReceived(event) => write!(f, "{}", event),
            DepositEvent::PayoutConfirmed(event) => write!(f, "{}", event),
            DepositEvent::NewBlock(event) => write!(f, "{}", event),
        }
    }
}

impl std::fmt::Display for UserTakeBackEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserTakeBack via {}", self.tx.compute_txid())
    }
}

impl std::fmt::Display for NonceReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NonceReceived from operator_idx: {}", self.operator_idx)
    }
}

impl std::fmt::Display for PartialReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PartialReceived from operator_idx: {}",
            self.operator_idx
        )
    }
}

impl std::fmt::Display for DepositConfirmedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DepositConfirmed")
    }
}

impl std::fmt::Display for WithdrawalAssignedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Assignment")
    }
}

impl std::fmt::Display for FulfillmentConfirmedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FulfillmentConfirmed")
    }
}

impl std::fmt::Display for PayoutDescriptorReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PayoutDescriptorReceived")
    }
}

impl std::fmt::Display for PayoutNonceReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PayoutNonceReceived")
    }
}

impl std::fmt::Display for PayoutPartialReceivedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PayoutPartialReceived")
    }
}

impl std::fmt::Display for PayoutConfirmedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PayoutConfirmed via {}", self.tx.compute_txid())
    }
}

impl std::fmt::Display for NewBlockEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NewBlock at height {}", self.block_height)
    }
}
