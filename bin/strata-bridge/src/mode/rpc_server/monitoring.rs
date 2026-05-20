//! Helpers that derive monitoring RPC responses from recovered state-machine state.

use bitcoin::{PublicKey, Txid};
use secp256k1::schnorr;
use strata_bridge_orchestrator::sm_registry::SMRegistry;
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_rpc::types::{
    RpcActiveClaim, RpcAggregateSignatures, RpcBridgeDutyStatus, RpcClaimPhase, RpcGraphData,
    RpcReimbursementStatus, RpcStakeState, RpcWithdrawalStatus,
};
use strata_bridge_sm::{
    deposit::state::DepositState,
    graph::{config::GraphSMCfg, context::GraphSMCtx, state::GraphState},
    stake::state::StakeState,
};

pub(super) const fn stake_state_to_rpc(state: &StakeState) -> RpcStakeState {
    match state {
        StakeState::Created { .. } => RpcStakeState::Created,
        StakeState::StakeGraphGenerated { .. } => RpcStakeState::StakeGraphGenerated,
        StakeState::UnstakingNoncesCollected { .. } => RpcStakeState::UnstakingNoncesCollected,
        StakeState::UnstakingSigned { .. } => RpcStakeState::UnstakingSigned,
        StakeState::Confirmed { summary, .. } => RpcStakeState::Confirmed {
            stake_txid: summary.stake,
        },
        StakeState::PreimageRevealed { .. } => RpcStakeState::PreimageRevealed,
        StakeState::Unstaked { unstaking_txid, .. } => RpcStakeState::Unstaked {
            unstaking_txid: *unstaking_txid,
        },
        StakeState::Slashed { slash_txid, .. } => RpcStakeState::Slashed {
            slash_txid: *slash_txid,
        },
    }
}

pub(super) const fn get_assigned_operator(state: &DepositState) -> Option<OperatorIdx> {
    match state {
        DepositState::Assigned { assignee, .. }
        | DepositState::Fulfilled { assignee, .. }
        | DepositState::PayoutDescriptorReceived { assignee, .. }
        | DepositState::PayoutNoncesCollected { assignee, .. }
        | DepositState::CooperativePathFailed { assignee, .. } => Some(*assignee),
        _ => None,
    }
}

/// Builds the deposit and withdrawal duties currently implied by a single deposit state machine.
pub(super) fn bridge_duties_for_deposit(
    deposit_idx: DepositIdx,
    state: &DepositState,
    deposit_request_txid: Txid,
) -> Vec<RpcBridgeDutyStatus> {
    let mut duties = Vec::new();

    if has_deposit_duty(state) {
        duties.push(RpcBridgeDutyStatus::Deposit {
            deposit_idx,
            deposit_request_txid,
        });
    }

    if let DepositState::Assigned { assignee, .. } = state {
        duties.push(RpcBridgeDutyStatus::Withdrawal {
            deposit_idx,
            assigned_operator_idx: *assignee,
        });
    }

    duties
}

/// Returns whether the deposit state still requires operators to publish the deposit transaction.
const fn has_deposit_duty(state: &DepositState) -> bool {
    matches!(
        state,
        DepositState::Created { .. }
            | DepositState::GraphGenerated { .. }
            | DepositState::DepositNoncesCollected { .. }
            | DepositState::DepositPartialsCollected { .. }
    )
}

/// Returns whether a bridge duty applies to a resolved operator index.
pub(super) const fn duty_applies_to_operator(
    duty: &RpcBridgeDutyStatus,
    operator_idx: OperatorIdx,
) -> bool {
    match duty {
        RpcBridgeDutyStatus::Deposit { .. } => true,
        RpcBridgeDutyStatus::Withdrawal {
            assigned_operator_idx,
            ..
        } => *assigned_operator_idx == operator_idx,
    }
}

/// Resolves a MuSig2 public key to an operator index using recovered deposit state-machine tables.
pub(super) fn operator_idx_from_registry(
    registry: &SMRegistry,
    operator_pk: &PublicKey,
) -> Option<OperatorIdx> {
    registry.deposits().find_map(|(_deposit_idx, sm)| {
        sm.context()
            .operator_table()
            .btc_key_to_idx(&operator_pk.inner)
    })
}

/// Derives the withdrawal RPC status from the deposit state.
pub(super) const fn withdrawal_status(deposit_state: &DepositState) -> Option<RpcWithdrawalStatus> {
    match deposit_state {
        // Unassigned states
        DepositState::Created { .. }
        | DepositState::GraphGenerated { .. }
        | DepositState::DepositNoncesCollected { .. }
        | DepositState::DepositPartialsCollected { .. }
        | DepositState::Deposited { .. } => None,

        // Withdrawal in progress states
        DepositState::Assigned { .. } => Some(RpcWithdrawalStatus::InProgress),

        // Withdrawal completed states
        DepositState::Fulfilled {
            fulfillment_txid, ..
        }
        | DepositState::PayoutDescriptorReceived {
            fulfillment_txid, ..
        }
        | DepositState::PayoutNoncesCollected {
            fulfillment_txid, ..
        }
        | DepositState::CooperativePathFailed {
            fulfillment_txid, ..
        } => Some(RpcWithdrawalStatus::Complete {
            fulfillment_txid: *fulfillment_txid,
        }),

        // Terminal states
        DepositState::Spent {
            fulfillment_txid: Some(fulfillment_txid),
        } => Some(RpcWithdrawalStatus::Complete {
            fulfillment_txid: *fulfillment_txid,
        }),
        DepositState::Spent {
            fulfillment_txid: None,
        }
        | DepositState::Aborted => None,
    }
}

/// Converts a graph state into the reimbursement status exposed by the monitoring RPC.
pub(super) const fn reimbursement_status(state: &GraphState) -> RpcReimbursementStatus {
    match state {
        GraphState::Claimed { graph_summary, .. } => RpcReimbursementStatus::InProgress {
            claim_txid: graph_summary.claim,
            phase: RpcClaimPhase::Claimed,
        },
        GraphState::Contested { graph_summary, .. } => RpcReimbursementStatus::InProgress {
            claim_txid: graph_summary.claim,
            phase: RpcClaimPhase::Contested,
        },
        GraphState::BridgeProofPosted { graph_summary, .. } => RpcReimbursementStatus::InProgress {
            claim_txid: graph_summary.claim,
            phase: RpcClaimPhase::BridgeProofPosted,
        },
        GraphState::BridgeProofTimedout { claim_txid, .. } => RpcReimbursementStatus::InProgress {
            claim_txid: *claim_txid,
            phase: RpcClaimPhase::BridgeProofTimedout,
        },
        GraphState::CounterProofPosted { graph_summary, .. } => {
            RpcReimbursementStatus::InProgress {
                claim_txid: graph_summary.claim,
                phase: RpcClaimPhase::CounterProofPosted,
            }
        }
        GraphState::AllNackd { claim_txid, .. } => RpcReimbursementStatus::InProgress {
            claim_txid: *claim_txid,
            phase: RpcClaimPhase::AllNackd,
        },
        GraphState::Acked { claim_txid, .. } => RpcReimbursementStatus::InProgress {
            claim_txid: *claim_txid,
            phase: RpcClaimPhase::Acked,
        },
        GraphState::Withdrawn {
            claim_txid,
            payout_txid,
        } => RpcReimbursementStatus::Complete {
            claim_txid: *claim_txid,
            payout_txid: *payout_txid,
        },
        GraphState::Slashed { claim_txid, .. } => RpcReimbursementStatus::Slashed {
            claim_txid: *claim_txid,
        },
        GraphState::Aborted { claim_txid, .. } => RpcReimbursementStatus::Aborted {
            claim_txid: *claim_txid,
        },
        _ => RpcReimbursementStatus::NotStarted,
    }
}

pub(super) const fn active_claim_from_state(
    operator: OperatorIdx,
    state: &GraphState,
) -> Option<RpcActiveClaim> {
    let (claim_txid, fulfillment_txid, phase) = match state {
        GraphState::Claimed {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::Claimed,
        ),
        GraphState::Contested {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::Contested,
        ),
        GraphState::BridgeProofPosted {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::BridgeProofPosted,
        ),
        GraphState::BridgeProofTimedout {
            claim_txid,
            fulfillment_txid,
            ..
        } => (
            *claim_txid,
            fulfillment_txid,
            RpcClaimPhase::BridgeProofTimedout,
        ),
        GraphState::CounterProofPosted {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::CounterProofPosted,
        ),
        GraphState::AllNackd {
            claim_txid,
            fulfillment_txid,
            ..
        } => (*claim_txid, fulfillment_txid, RpcClaimPhase::AllNackd),
        GraphState::Acked {
            claim_txid,
            fulfillment_txid,
            ..
        } => (*claim_txid, fulfillment_txid, RpcClaimPhase::Acked),
        _ => return None,
    };

    Some(RpcActiveClaim {
        operator,
        claim_txid,
        fulfilled: fulfillment_txid.is_some(),
        phase,
    })
}

pub(super) fn graph_data_response(
    context: &GraphSMCtx,
    state: &GraphState,
    graph_cfg: &GraphSMCfg,
) -> Option<RpcGraphData> {
    let graph_data = graph_data_from_state(state)?;
    let setup = context.generate_setup_params(graph_cfg, graph_data);

    Some(RpcGraphData {
        context: context.clone(),
        setup,
        deposit: graph_data.clone(),
    })
}

pub(super) fn aggregate_signatures_response(
    graph_idx: GraphIdx,
    state: &GraphState,
) -> Option<RpcAggregateSignatures> {
    let signatures = aggregate_signatures_from_state(state)?;

    Some(RpcAggregateSignatures {
        graph_idx,
        signatures: signatures.to_vec(),
    })
}

const fn graph_data_from_state(
    state: &GraphState,
) -> Option<&strata_bridge_tx_graph::game_graph::DepositParams> {
    match state {
        GraphState::GraphGenerated { graph_data, .. }
        | GraphState::AdaptorsVerified { graph_data, .. }
        | GraphState::NoncesCollected { graph_data, .. }
        | GraphState::GraphSigned { graph_data, .. }
        | GraphState::Assigned { graph_data, .. }
        | GraphState::Fulfilled { graph_data, .. }
        | GraphState::Claimed { graph_data, .. }
        | GraphState::Contested { graph_data, .. }
        | GraphState::BridgeProofPosted { graph_data, .. }
        | GraphState::BridgeProofTimedout { graph_data, .. }
        | GraphState::CounterProofPosted { graph_data, .. } => Some(graph_data),
        _ => None,
    }
}

fn aggregate_signatures_from_state(state: &GraphState) -> Option<&[schnorr::Signature]> {
    match state {
        GraphState::GraphSigned { signatures, .. }
        | GraphState::Assigned { signatures, .. }
        | GraphState::Fulfilled { signatures, .. }
        | GraphState::Claimed { signatures, .. }
        | GraphState::Contested { signatures, .. }
        | GraphState::BridgeProofPosted { signatures, .. }
        | GraphState::BridgeProofTimedout { signatures, .. }
        | GraphState::CounterProofPosted { signatures, .. } => Some(signatures),
        _ => None,
    }
}
