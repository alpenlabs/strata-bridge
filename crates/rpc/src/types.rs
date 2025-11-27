//! Types for the RPC server.

use bitcoin::{hashes::sha256, taproot, OutPoint, Txid};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{types::OperatorIdx, wots};
use strata_primitives::{bitcoin_bosd::Descriptor, buf::Buf32};

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

/// The data shared during deposit setup required to construct a disprove transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDisproveData {
    /// The transaction ID of the post-assert transaction.
    pub post_assert_txid: Txid,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,

    /// The outpoint of the stake transaction that is being spent.
    pub stake_outpoint: OutPoint,

    /// The hash for the hashlock in the stake transaction.
    pub stake_hash: sha256::Hash,

    /// The operator descriptor that locks the stake transaction.
    pub operator_descriptor: Descriptor,

    /// The WOTS public keys whose private keys were used by the operator to sign their proof
    /// assertions.
    pub wots_public_keys: wots::PublicKeys,

    /// The N-of-N signature used to finalize the first input in the disprove transaction.
    pub n_of_n_sig: taproot::Signature,
}
