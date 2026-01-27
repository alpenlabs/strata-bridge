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

/// The external events that affect the Deposit State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositEvent {
    /// Event signifying that the output of the deposit request was spent by the user instead of the
    /// bridge covenant.
    UserTakeBack {
        /// The transaction that spends the deposit request.
        tx: Transaction,
    },
    /// Message received from the Graph State Machine.
    GraphMessage(GraphToDeposit),
    /// Nonce received from an operator for the deposit transaction signing
    NonceReceived {
        /// The public nonce provided by the operator
        nonce: PubNonce,
        /// The index of the operator who provided the nonce
        operator_idx: OperatorIdx,
    },
    /// Partial signature received from an operator for the deposit transaction signing
    PartialReceived {
        /// The partial signature provided by the operator
        partial_sig: PartialSignature,
        /// The index of the operator who provided the partial signature
        operator_idx: OperatorIdx,
    },
    /// This event notifies that the deposit has been confirmed on-chain.
    DepositConfirmed {
        /// The deposit transaction that has been confirmed on-chain.
        deposit_transaction: Transaction,
    },
    /// This event notifies that the withdrawal request has been assigned to some operator for
    /// fulfillment.
    WithdrawalAssigned {
        /// The index of the operator assigned to serve the withdrawal request.
        assignee: OperatorIdx,
        /// The block height until which the assignment is valid.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
    },
    /// This event notifies that the fulfillment transaction has been confirmed on-chain.
    FulfillmentConfirmed {
        /// The fulfillment transaction that has been confirmed on-chain
        fulfillment_transaction: Transaction,
        /// The block height at which the fulfillment transaction was confirmed.
        fulfillment_height: BitcoinBlockHeight,
    },
    /// This event notifies that the output descriptor of the operator for the cooperative payout
    /// has been received.
    PayoutDescriptorReceived {
        /// The output descriptor of the operator where the funds for the cooperative payout are to
        /// be received.
        operator_desc: Descriptor,
    },
    /// This event notifies that a pubnonce from some operator for the cooperative payout
    /// transaction has been received.
    PayoutNonceReceived {
        /// The pubnonce for the cooperative payout transaction that was received.
        payout_nonce: PubNonce,
        /// The operator who sent the pubnonce.
        operator_idx: OperatorIdx,
    },
    /// This event notifies that a partial signature from some operator for the cooperative payout
    /// transaction has been received.
    PayoutPartialReceived {
        /// The partial signature for the cooperative payout transaction that was received.
        partial_signature: PartialSignature,
        /// The operator who sent the partial signature.
        operator_idx: OperatorIdx,
    },
    /// TODO: (@Rajil1213)
    PayoutConfirmed {
        /// The transaction that confirms the payout.
        tx: Transaction,
    },
    /// Event signalling that a new block has been observed on chain.
    ///
    /// This is required to deal with timelocks in various states and to track the last observed
    /// block.
    NewBlock {
        /// The new block.
        block_height: BitcoinBlockHeight,
    },
}

impl std::fmt::Display for DepositEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let event_str = match self {
            DepositEvent::UserTakeBack { tx } => {
                return write!(f, "UserTakeBack via {}", tx.compute_txid());
            }
            DepositEvent::GraphMessage(graph_msg) => match graph_msg {
                GraphToDeposit::GraphAvailable { operator_idx } => {
                    return write!(f, "GraphAvailable for operator_idx: {}", operator_idx);
                }
            },
            DepositEvent::NonceReceived { operator_idx, .. } => {
                return write!(f, "NonceReceived from operator_idx: {}", operator_idx);
            }
            DepositEvent::PartialReceived { operator_idx, .. } => {
                return write!(f, "PartialReceived from operator_idx: {}", operator_idx);
            }
            DepositEvent::DepositConfirmed { .. } => "DepositConfirmed",
            DepositEvent::WithdrawalAssigned { .. } => "Assignment",
            DepositEvent::FulfillmentConfirmed { .. } => "FulfillmentConfirmed",
            DepositEvent::PayoutDescriptorReceived { .. } => "PayoutDescriptorReceived",
            DepositEvent::PayoutNonceReceived { .. } => "PayoutNonceReceived",
            DepositEvent::PayoutPartialReceived { .. } => "PayoutPartialReceived",
            DepositEvent::PayoutConfirmed { tx } => {
                return write!(f, "PayoutConfirmed via {}", tx.compute_txid());
            }
            DepositEvent::NewBlock { block_height } => {
                return write!(f, "NewBlock at height {}", block_height);
            }
        };

        write!(f, "{}", event_str)
    }
}
