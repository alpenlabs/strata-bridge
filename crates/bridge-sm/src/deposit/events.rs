//! The events that are relevant to the Deposit State Machine.
//!
//! Depending upon the exact state that the state machine is in, these events will trigger
//! different transitions and emit duties that need to be performed and messages that need to be
//! propagated.

use musig2::PubNonce;
use strata_bridge_primitives::types::OperatorIdx;

use crate::signals::GraphToDeposit;

/// The external events that affect the Deposit State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DepositEvent {
    /// TODO: (@MdTeach)
    DepositRequest,
    /// TODO: (@MdTeach)
    GraphMessage(GraphToDeposit),
    /// Nonce received from an operator for the deposit transaction signing
    NonceReceived {
        /// The public nonce provided by the operator
        nonce: PubNonce,
        /// The index of the operator who provided the nonce
        operator_idx: OperatorIdx,
    },
    /// TODO: (@MdTeach)
    PartialReceived,
    /// TODO: (@mukeshdroid)
    DepositConfirmed,
    /// TODO: (@mukeshdroid)
    Assignment,
    /// TODO: (@mukeshdroid)
    FulfillmentConfirmed,
    /// TODO: (@mukeshdroid)
    PayoutNonceReceived,
    /// TODO: (@mukeshdroid)
    PayoutPartialReceived,
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
            DepositEvent::NonceReceived { operator_idx, .. } => {
                return write!(f, "NonceReceived from operator_idx: {}", operator_idx);
            },
            DepositEvent::PartialReceived => "PartialReceived",
            DepositEvent::DepositConfirmed => "DepositConfirmed",
            DepositEvent::Assignment => "Assignment",
            DepositEvent::FulfillmentConfirmed => "FulfillmentConfirmed",
            DepositEvent::PayoutNonceReceived => "PayoutNonceReceived",
            DepositEvent::PayoutPartialReceived => "PayoutPartialReceived",
            DepositEvent::PayoutConfirmed => "PayoutConfirmed",
            DepositEvent::NewBlock => "NewBlock",
        };

        write!(f, "{}", event_str)
    }
}
