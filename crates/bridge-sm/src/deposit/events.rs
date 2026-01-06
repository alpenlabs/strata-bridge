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
    /// TODO: (@MdTeach)
    DepositRequest,
    /// TODO: (@MdTeach)
    GraphMessage(GraphToDeposit),
    /// TODO: (@MdTeach)
    NonceReceived,
    /// TODO: (@MdTeach)
    PartialReceived,
    /// This event notifies that the deposit has been confirmed on-chain.
    DepositConfirmed {
        /// The Deposit transaction that has been confirmed on-chain.
        deposit_transaction: Transaction,
    },
    /// This event notifies that the deposit has been assigned to some operator for
    /// fulfillment.
    Assignment {
        /// The index of the operator assigned to front the user.
        assignee: OperatorIdx,
        /// The block height by which the operator must fulfill the withdrawal.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
    },
    /// This event notifies that the fulfillment has been confirmed on-chain.
    FulfillmentConfirmed {
        /// The fulfillment transaction, confirmed on-chain, in which the user was fronted.
        fulfillment_transaction: Transaction,
        /// The block height at which the fulfillment transaction was confirmed.
        fulfillment_block_height: BitcoinBlockHeight,
    },
    /// This event notifies that the output descriptor of the operator for the cooperative payout
    /// has been received.
    PayoutDescriptorReceived {
        /// The output descriptor of the operator where the funds for the cooperative payout is to
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
    PayoutConfirmed,
    /// TODO: (@Rajil1213)
    NewBlock,
}

impl std::fmt::Display for DepositEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let event_str = match self {
            DepositEvent::DepositRequest => "DepositRequest",
            DepositEvent::GraphMessage(graph_msg) => match graph_msg {
                GraphToDeposit::GraphAvailable { operator_idx } => {
                    return write!(f, "GraphAvailable for operator_idx: {}", operator_idx);
                }
            },
            DepositEvent::NonceReceived => "NonceReceived",
            DepositEvent::PartialReceived => "PartialReceived",
            DepositEvent::DepositConfirmed { .. } => "DepositConfirmed",
            DepositEvent::Assignment { .. } => "Assignment",
            DepositEvent::FulfillmentConfirmed { .. } => "FulfillmentConfirmed",
            DepositEvent::PayoutDescriptorReceived { .. } => "PayoutDescriptorReceived",
            DepositEvent::PayoutNonceReceived { .. } => "PayoutNonceReceived",
            DepositEvent::PayoutPartialReceived { .. } => "PayoutPartialReceived",
            DepositEvent::PayoutConfirmed => "PayoutConfirmed",
            DepositEvent::NewBlock => "NewBlock",
        };

        write!(f, "{}", event_str)
    }
}
