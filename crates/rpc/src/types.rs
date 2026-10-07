//! Types for the RPC server.

use bitcoin::Txid;
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_sm::{graph::context::GraphSMCtx, stake::context::StakeSMCtx};
use strata_bridge_tx_graph::{
    game_graph::{DepositParams, SetupParams},
    stake_graph::{ProtocolParams as StakeProtocolParams, SetupParams as StakeSetupParams},
};

/// Enum representing the status of a bridge operator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcOperatorStatus {
    /// Operator is online and ready to process transactions.
    Online,

    /// Operator is offline and not processing transactions.
    Offline,
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2704>
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

/// Represents a valid withdrawal status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcWithdrawalStatus {
    /// Withdrawal is assigned or being processed, and no fulfillment transaction is known yet.
    InProgress,

    /// Withdrawal has been fulfilled.
    Complete {
        /// Transaction ID of the operator's withdrawal fulfillment transaction.
        fulfillment_txid: Txid,
    },
}

/// Represents a valid reimbursement status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcReimbursementStatus {
    /// No reimbursement claim has been observed for this deposit's assigned operator.
    NotStarted,

    /// Reimbursement claim has been observed and is still in a non-terminal game phase.
    InProgress {
        /// Transaction ID of the reimbursement claim transaction.
        claim_txid: Txid,

        /// Current non-terminal phase of the challenge-response game for this claim.
        phase: RpcClaimPhase,
    },

    /// Operator was slashed for this reimbursement claim.
    Slashed {
        /// Transaction ID of the slashed reimbursement claim transaction.
        claim_txid: Txid,
    },

    /// Reimbursement claim path was aborted before payout or slashing completed.
    Aborted {
        /// Transaction ID of the aborted reimbursement claim transaction.
        claim_txid: Txid,
    },

    /// Reimbursement claim completed and paid out.
    Complete {
        /// Transaction ID of the reimbursed claim transaction.
        claim_txid: Txid,

        /// Transaction ID of the reimbursement payout transaction.
        payout_txid: Txid,
    },
}

/// Represents deposit transaction details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDepositInfo {
    /// Status of the deposit.
    pub status: RpcDepositStatus,

    /// Bridge deposit index.
    pub deposit_idx: DepositIdx,

    /// Transaction ID of the deposit request transaction (DRT).
    pub deposit_request_txid: Txid,
}

/// Represents a valid bridge duty status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcBridgeDutyStatus {
    /// Deposit duty
    Deposit {
        /// Bridge deposit index.
        deposit_idx: DepositIdx,

        /// Transaction ID of the deposit request transaction (DRT).
        deposit_request_txid: Txid,
    },

    /// Withdrawal duty
    Withdrawal {
        /// Bridge deposit index.
        deposit_idx: DepositIdx,

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

/// Stake data needed to reconstruct an operator's stake graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcStakeData {
    /// Stake state machine context used for stake graph construction.
    pub context: StakeSMCtx,

    /// Protocol parameters used to construct the stake graph.
    pub protocol: StakeProtocolParams,

    /// Setup parameters required to construct the stake graph.
    pub setup: StakeSetupParams,
}

/// Aggregate signatures needed to finalize presigned transactions in the stake graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcStakeAggregateSignatures {
    /// Operator whose stake graph the signatures belong to.
    pub operator_idx: OperatorIdx,

    /// Aggregate Schnorr signatures for the stake graph.
    pub signatures: Vec<Signature>,
}

/// Lifecycle state of an operator's stake.
///
/// The variants mirror [`strata_bridge_sm::stake::state::StakeState`] but carry only the
/// information needed for external monitoring: the coarse phase label and, once available, the
/// unstaking transaction id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RpcStakeState {
    /// Initial state; no stake-related transactions have been produced yet.
    Created,

    /// Stake graph has been generated.
    StakeGraphGenerated,

    /// Unstaking musig2 nonces have been collected.
    UnstakingNoncesCollected,

    /// Unstaking musig2 partial signatures have been collected.
    UnstakingSigned,

    /// Stake transaction has been confirmed on-chain.
    Confirmed {
        /// Txid of the confirmed stake transaction.
        stake_txid: Txid,
    },

    /// Unstaking preimage has been revealed on-chain.
    PreimageRevealed,

    /// Unstaking transaction has been confirmed on-chain.
    Unstaked {
        /// Txid of the confirmed unstaking transaction.
        unstaking_txid: Txid,
    },

    /// Stake has been slashed by another operator.
    Slashed {
        /// Txid of the confirmed slash transaction.
        slash_txid: Txid,
    },
}

/// Per-operator stake status.
///
/// The [`RpcStakeState`] discriminator + fields are flattened into this struct, so a `Confirmed`
/// stake serialises as
/// `{"operator_idx": 0, "state": "confirmed", "stake_txid": "…"}` rather than nesting the state
/// under a sub-object. This keeps the JSON readable and easy to parse in consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcOperatorStakeInfo {
    /// The operator this stake belongs to.
    pub operator_idx: OperatorIdx,

    /// Current stake state.
    #[serde(flatten)]
    pub state: RpcStakeState,
}
