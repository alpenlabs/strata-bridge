use bitcoin::Txid;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::{BitcoinBlockHeight, OperatorIdx};

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcOperatorStatus {
    Online,
    Offline,
}

/// Represents a valid deposit status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcDepositStatus {
    /// Deposit exists, but minting hasn't happened yet.
    InProgress { deposit_request_txid: Txid },

    /// Deposit exists, but was never completed (can be reclaimed).
    Failed {
        deposit_request_txid: Txid,
        failure_reason: String,
    },

    /// Deposit has been fully processed and minted.
    Complete {
        deposit_request_txid: Txid,
        deposit_txid: Txid,
    },
}

/// Challenge step states for claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStep {
    Claim,
    Challenge,
    Assert,
}

/// Represents a valid withdrawal status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcWithdrawalStatus {
    InProgress,
    Complete { fulfillment_txid: Txid },
}

/// Represents a valid reimbursement status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcReimbursementStatus {
    /// Claim exists, challenge step is "Claim", no payout.
    InProgress { challenge_step: ChallengeStep },

    /// Claim exists, challenge step is "Challenge" or "Assert", no payout.
    Challenged { challenge_step: ChallengeStep },

    /// Operator was slashed, claim is no longer valid.
    Cancelled,

    /// Claim has been successfully reimbursed.
    Complete { payout_txid: Txid },
}

/// Represents deposit transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDepositInfo {
    pub status: RpcDepositStatus,
}

/// Represents withdrawal transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcWithdrawalInfo {
    pub status: RpcWithdrawalStatus,
}

/// Represents reimbursement transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcClaimInfo {
    pub claim_txid: Txid,
    pub status: RpcReimbursementStatus,
}
