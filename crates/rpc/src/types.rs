//! Types for the RPC server.

use bitcoin::Txid;
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::{GraphIdx, OperatorIdx};
use strata_bridge_sm::graph::context::GraphSMCtx;
use strata_bridge_tx_graph::game_graph::{DepositParams, SetupParams};
use strata_primitives::buf::Buf32;

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcOperatorStatus {
    /// Operator is online and ready to process transactions.
    Online,

    /// Operator is offline and not processing transactions.
    Offline,
    // TODO: <https://atlassian.alpenlabs.net/browse/STR-2704>
    // Add a `Faulty` status.
}

/// Represents a valid deposit status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcDepositStatus {
    /// Deposit exists, but minting hasn't happened yet.
    InProgress,

    /// Deposit exists, but was never completed (can be reclaimed).
    Failed {
        /// Reason for the failure.
        reason: String,
    },

    /// Deposit has been fully processed and minted.
    Complete {
        /// Transaction ID of the deposit transaction (DT).
        deposit_txid: Txid,
    },
}

/// Challenge step states for claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStep {
    /// Challenge step is "Claim".
    Claim,

    /// Challenge step is "Challenge".
    Challenge,

    /// Challenge step is "Assert".
    Assert,
}

/// Represents a valid withdrawal status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcWithdrawalStatus {
    /// Withdrawal is in progress.
    InProgress,

    /// Withdrawal has been fully processed and fulfilled.
    Complete {
        /// Transaction ID of the withdrawal fulfillment transaction.
        fulfillment_txid: Txid,
    },
}

/// Represents a valid reimbursement status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcReimbursementStatus {
    /// Claim does not exist on-chain.
    NotStarted,

    /// Claim exists, challenge step is "Claim", no payout.
    InProgress {
        /// Challenge step.
        challenge_step: ChallengeStep,
    },

    /// Claim exists, challenge step is "Challenge" or "Assert", no payout.
    Challenged {
        /// Challenge step.
        challenge_step: ChallengeStep,
    },

    /// Operator was slashed, claim is no longer valid.
    Cancelled,

    /// Claim has been successfully reimbursed.
    Complete {
        /// Payout transaction ID.
        payout_txid: Txid,
    },
}

/// Represents deposit transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDepositInfo {
    /// Status of the deposit.
    pub status: RpcDepositStatus,

    /// Transaction ID of the deposit request transaction (DRT).
    pub deposit_request_txid: Txid,
}

/// Represents withdrawal transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcWithdrawalInfo {
    /// Status of the withdrawal.
    pub status: RpcWithdrawalStatus,

    /// Transaction ID of the withdrawal request transaction (WRT).
    ///
    /// NOTE: This is not a Bitcoin [`Txid`] but a [`Buf32`] representing the transaction ID of the
    /// withdrawal transaction in the sidesystem's execution environment.
    pub withdrawal_request_txid: Buf32,
}

/// Represents reimbursement transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcClaimInfo {
    /// Transaction ID of the claim transaction.
    pub claim_txid: Txid,

    /// Status of the reimbursement.
    pub status: RpcReimbursementStatus,
}

/// Represents a valid bridge duty status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcBridgeDutyStatus {
    /// Deposit duty
    Deposit {
        /// Transaction ID of the deposit request transaction (DRT).
        deposit_request_txid: Txid,
    },

    /// Withdrawal duty
    Withdrawal {
        /// Transaction ID of the withdrawal request transaction (WRT).
        ///
        /// NOTE: This is not a Bitcoin [`Txid`] but a [`Buf32`] representing the transaction ID of
        /// the withdrawal transaction in the sidesystem's execution environment.
        withdrawal_request_txid: Buf32,

        /// Assigned operator index.
        assigned_operator_idx: OperatorIdx,
    },
}

/// The information about a particular deposit associated with a withdrawal request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcPendingWithdrawalInfo {
    /// The index of the assigned operator.
    pub assigned_operator: OperatorIdx,

    /// The assigned operator's reimbursement claim, if active.
    pub assigned_claim: Option<RpcActiveClaim>,

    /// Claims from non-assigned operators (faulty by definition).
    pub competing_claims: Vec<RpcActiveClaim>,
}

/// A single active reimbursement process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcActiveClaim {
    /// The operator who made this claim.
    pub operator: OperatorIdx,

    /// The claim transaction ID.
    pub claim_txid: Txid,

    /// Whether this operator fulfilled the withdrawal before claiming.
    ///
    /// `false` means the claim is faulty regardless of who made it.
    pub fulfilled: bool,

    /// Current phase of this claim in the challenge-response game.
    pub phase: RpcClaimPhase,
}

/// Where an active claim sits in the challenge-response game.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcClaimPhase {
    /// Claim transaction confirmed on chain.
    Claimed,
    /// Contest transaction confirmed on chain.
    Contested,
    /// Operator's bridge proof posted on chain.
    BridgeProofPosted,
    /// Bridge proof timed out without valid proof.
    BridgeProofTimedout,
    /// Counter-proof posted by watchtowers.
    CounterProofPosted,
    /// All counter-proofs NACK'd on chain.
    AllNackd,
    /// A counter-proof ACK'd on chain.
    Acked,
}

/// Graph data needed to reconstruct a game graph for a graph instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcGraphData {
    /// Graph state machine context used for graph construction.
    pub context: GraphSMCtx,

    /// Non-protocol setup parameters required to construct the graph.
    pub setup: SetupParams,

    /// Deposit-time parameters required to construct the graph.
    pub deposit: DepositParams,
}

/// Aggregate signatures needed to finalize presigned graph transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcAggregateSignatures {
    /// Graph identifier for the claim.
    pub graph_idx: GraphIdx,

    /// Aggregate Schnorr signatures for the graph.
    pub signatures: Vec<Signature>,
}
