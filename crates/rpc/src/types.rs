//! Types for the RPC server.

use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::OperatorIdx;

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcOperatorStatus {
    /// Operator is online and ready to process transactions.
    Online,

    /// Operator is offline and not processing transactions.
    Offline,
    // TODO add faulty.
}

/// Represents a valid deposit status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcDepositStatus {
    /// Deposit exists, but minting hasn't happened yet.
    InProgress {
        /// Transaction ID of the deposit request transaction (DRT).
        deposit_request_txid: Txid,
    },

    /// Deposit exists, but was never completed (can be reclaimed).
    Failed {
        /// Transaction ID of the deposit request transaction (DRT).
        deposit_request_txid: Txid,

        /// Reason for the failure.
        failure_reason: String,
    },

    /// Deposit has been fully processed and minted.
    Complete {
        /// Transaction ID of the deposit request transaction (DRT).
        deposit_request_txid: Txid,

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
    /// Claim exists, challenge step is "Claim", no payout.
    InProgress,

    /// Claim exists, challenge step is "Challenge" or "Assert", no payout.
    Challenged,

    /// Operator was slashed, claim is no longer valid.
    Cancelled,

    /// Claim has been successfully reimbursed.
    Complete,
}

/// Represents deposit transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDepositInfo {
    /// Status of the deposit.
    pub status: RpcDepositStatus,
}

/// Represents withdrawal transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcWithdrawalInfo {
    /// Status of the withdrawal.
    pub status: RpcWithdrawalStatus,
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
        withdrawal_request_txid: Txid,

        /// Assigned operator index.
        assigned_operator_idx: OperatorIdx,
    },
}
