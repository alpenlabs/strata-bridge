use bitcoin::Txid;
use serde::{Deserialize, Serialize};

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcOperatorStatus {
    /// Meant to represent functional as opposed to faulty.
    Online,
    /// Not responding
    Offline,
    // TODO add faulty.
}

/// Represents a valid deposit status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcDepositStatus {
    /// Deposit exists, but minting hasn't happened yet.
    InProgress {
        /// Deposit request transaction id
        deposit_request_txid: Txid,
    },

    /// Deposit exists, but was never completed (can be reclaimed).
    Failed {
        /// Deposit request transaction id
        deposit_request_txid: Txid,
        /// Why the deposit failed
        failure_reason: String,
    },

    /// Deposit has been fully processed and minted.
    Complete {
        /// Deposit request transaction id
        deposit_request_txid: Txid,
        /// Deposit transaction id
        deposit_txid: Txid,
    },
}

/// Challenge step states for claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStep {
    /// Claim
    Claim,
    /// Challenge
    Challenge,
    /// Assert
    Assert,
}

/// Represents a valid withdrawal status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcWithdrawalStatus {
    /// Being processed
    InProgress,
    /// Front payment has been made
    Complete {
        /// Fulfillment transaction id
        fulfillment_txid: Txid,
    },
}

/// Represents a valid reimbursement status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcReimbursementStatus {
    /// Claim exists, challenge step is "Claim", no payout.
    InProgress {
        /// Challenge step
        challenge_step: ChallengeStep,
    },

    /// Claim exists, challenge step is "Challenge" or "Assert", no payout.
    Challenged {
        /// Challenge step
        challenge_step: ChallengeStep,
    },

    /// Operator was slashed, claim is no longer valid.
    Cancelled,

    /// Claim has been successfully reimbursed.
    Complete {
        /// Payout transaction id
        payout_txid: Txid,
    },
}

/// Represents deposit transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDepositInfo {
    /// Deposit status
    pub status: RpcDepositStatus,
}

/// Represents withdrawal transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcWithdrawalInfo {
    /// Withdrawal status
    pub status: RpcWithdrawalStatus,
}

/// Represents reimbursement transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcClaimInfo {
    /// Claim transaction id
    pub claim_txid: Txid,
    /// Reimbursement status
    pub status: RpcReimbursementStatus,
}
