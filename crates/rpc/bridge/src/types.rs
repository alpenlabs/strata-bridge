use bitcoin::Txid;
use serde::{Deserialize, Serialize};

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RpcOperatorStatus {
    Online,
    Offline,
}

/// Represents a valid deposit status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum RpcDepositStatus {
    /// Deposit exists, but minting hasn't happened yet.
    #[serde(rename = "In progress")]
    InProgress {
        deposit_request_txid: Txid,
        deposit_txid: Option<Txid>,
    },

    /// Deposit exists, but was never completed (can be reclaimed).
    #[serde(rename = "Failed")]
    Failed { deposit_request_txid: Txid },

    /// Deposit has been fully processed and minted.
    #[serde(rename = "Complete")]
    Complete {
        deposit_request_txid: Txid,
        deposit_txid: Txid,
    },
}

/// Shared status and relevant info for withdrawals and claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum RpcWithdrawalStatus {
    /// Claim exists, no payout yet.
    #[serde(rename = "In progress")]
    InProgress { claim_txid: Txid },

    /// Claim exists, challenge step is "Challenge" or "Assert", no payout.
    #[serde(rename = "Challenged")]
    Challenged {
        claim_txid: Txid,
        challenge_step: ChallengeStep,
    },

    /// Operator was slashed, claim is no longer valid.
    #[serde(rename = "Cancelled")]
    Cancelled { claim_txid: Txid },

    /// Claim has been successfully reimbursed.
    #[serde(rename = "Complete")]
    Complete { claim_txid: Txid, payout_txid: Txid },
}

/// Represents deposit transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcDepositInfo {
    pub status: RpcDepositStatus,
}

/// Represents withdrawal transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcWithdrawalInfo {
    // Some withdrawals may still be pending
    pub fulfillment_txid: Option<Txid>,
    pub status: RpcWithdrawalStatus,
}

/// Challenge step states for claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ChallengeStep {
    Claim,
    Challenge,
    Assert,
}

/// Represents reimbursement claim details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcClaimInfo {
    pub status: RpcWithdrawalStatus,
}
