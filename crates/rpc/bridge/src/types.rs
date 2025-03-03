use bitcoin::Txid;
use serde::{Deserialize, Serialize};

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OperatorStatus {
    Online,
    Offline,
}

/// Transaction status variants with custom serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    #[serde(rename = "In progress")]
    InProgress,

    #[serde(rename = "Challenged")]
    Challenged,

    #[serde(rename = "Cancelled")]
    Cancelled,

    #[serde(rename = "Complete")]
    Complete,
}

/// Represents deposit transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcDepositInfo {
    pub deposit_request_txid: Txid,
    pub deposit_txid: Option<Txid>, // Some deposits may not have completed yet
    pub status: TransactionStatus,
}

/// Represents withdrawal transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcWithdrawalInfo {
    // Some withdrawals may still be pending
    pub fulfillment_txid: Option<Txid>,
    pub status: TransactionStatus,
}

/// Challenge step states for claims
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStep {
    Claim,
    Challenge,
    Assert,
}

/// Represents reimbursement claim details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcClaimInfo {
    pub claim_txid: Txid,
    pub challenge_step: ChallengeStep, // Fixed typo from "challege_step"
    pub payout_txid: Option<Txid>,     // Some claims may not have completed payout yet
    pub status: TransactionStatus,
}
