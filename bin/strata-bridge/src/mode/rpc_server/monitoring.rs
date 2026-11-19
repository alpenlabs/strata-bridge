//! Helpers that derive monitoring RPC responses from recovered state-machine state.

use anyhow::{Context, Result, bail};
use bitcoin::{PublicKey, Txid};
use secp256k1::schnorr;
use strata_bridge_orchestrator::{
    current_covenant::{Admission, CurrentCovenant},
    sm_registry::SMRegistry,
    stake_readiness::StakeShortfall,
};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_rpc::types::{
    RpcActiveClaim, RpcAggregateSignatures, RpcBridgeDutyStatus, RpcClaimPhase,
    RpcCovenantAdmission, RpcCurrentCovenant, RpcGraphData, RpcMemberShortfall, RpcPayoutBlock,
    RpcPayoutKind, RpcReimbursementStatus, RpcStakeShortfall, RpcStakeState, RpcWithdrawalStatus,
};
use strata_bridge_sm::{
    deposit::state::DepositState,
    graph::{
        config::GraphSMCfg,
        context::GraphSMCtx,
        state::{GraphState, PayoutKind},
    },
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

pub(super) fn current_covenant_response(current: CurrentCovenant) -> RpcCurrentCovenant {
    let CurrentCovenant {
        processed_height,
        block_covenant,
        admission,
    } = current;
    let admission = match admission {
        Admission::Ready => RpcCovenantAdmission::Ready {
            aggregate_pubkey: block_covenant.covenant.aggregate_pubkey,
        },
        Admission::SafeHarbour => RpcCovenantAdmission::SafeHarbour,
        Admission::DepositCapReached => RpcCovenantAdmission::DepositCapReached,
        Admission::Unready(shortfalls) => RpcCovenantAdmission::Unready {
            shortfalls: shortfalls
                .into_iter()
                .map(|(operator_idx, shortfall)| RpcMemberShortfall {
                    operator_idx,
                    reason: stake_shortfall_to_rpc(shortfall),
                })
                .collect(),
        },
        Admission::Unsettled(operators) => RpcCovenantAdmission::Unsettled {
            operators: operators.into_iter().collect(),
        },
    };
    RpcCurrentCovenant {
        processed_height,
        covenant: block_covenant.covenant,
        members: block_covenant
            .operator_table
            .operator_idxs()
            .into_iter()
            .collect(),
        admission,
    }
}

const fn stake_shortfall_to_rpc(shortfall: StakeShortfall) -> RpcStakeShortfall {
    match shortfall {
        StakeShortfall::Missing => RpcStakeShortfall::Missing,
        StakeShortfall::Unconfirmed => RpcStakeShortfall::Unconfirmed,
        StakeShortfall::Exited => RpcStakeShortfall::Exited,
        StakeShortfall::MembershipMismatch => RpcStakeShortfall::MembershipMismatch,
    }
}

pub(super) const fn get_pending_assigned_operator(state: &DepositState) -> Option<OperatorIdx> {
    match state {
        DepositState::Assigned { assignee, .. }
        | DepositState::Fulfilled { assignee, .. }
        | DepositState::PayoutDescriptorReceived { assignee, .. }
        | DepositState::PayoutNoncesCollected { assignee, .. }
        | DepositState::CooperativePathFailed { assignee, .. } => Some(*assignee),
        _ => None,
    }
}

/// Returns the operator whose graph should back reimbursement status for this deposit state.
pub(super) const fn get_reimbursement_operator(state: &DepositState) -> Option<OperatorIdx> {
    match state {
        DepositState::Spent {
            assignee: Some(assignee),
            ..
        } => Some(*assignee),
        _ => get_pending_assigned_operator(state),
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

/// Builds the bridge duties applicable to an operator key, scoped by each deposit's operator table.
pub(super) fn bridge_duties_for_operator_pk(
    registry: &SMRegistry,
    operator_pk: &PublicKey,
) -> Option<Vec<RpcBridgeDutyStatus>> {
    let mut found_operator = false;
    let mut duties = Vec::new();

    for (&deposit_idx, dsm) in registry.deposits() {
        let Some(operator_idx) = dsm
            .context()
            .operator_table()
            .btc_key_to_idx(&operator_pk.inner)
        else {
            continue;
        };

        found_operator = true;
        duties.extend(
            bridge_duties_for_deposit(
                deposit_idx,
                dsm.state(),
                dsm.context().deposit_request_outpoint().txid,
            )
            .into_iter()
            .filter(|duty| duty_applies_to_operator(duty, operator_idx)),
        );
    }

    found_operator.then_some(duties)
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

/// Derives the withdrawal RPC status from the deposit state.
pub(super) const fn withdrawal_status(deposit_state: &DepositState) -> Option<RpcWithdrawalStatus> {
    match deposit_state {
        // Unassigned states
        DepositState::Created { .. }
        | DepositState::GraphGenerated { .. }
        | DepositState::DepositNoncesCollected { .. }
        | DepositState::DepositPartialsCollected { .. }
        | DepositState::Deposited { .. }
        | DepositState::SweepNoncesPending { .. }
        | DepositState::SweepNoncesCollected { .. } => None,

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
            ..
        } => Some(RpcWithdrawalStatus::Complete {
            fulfillment_txid: *fulfillment_txid,
        }),
        DepositState::Spent {
            fulfillment_txid: None,
            ..
        }
        | DepositState::Aborted
        | DepositState::Skipped => None,
    }
}

/// Returns completion for an observed cooperative payout, before claim-graph lookup.
pub(super) const fn cooperative_reimbursement_status(
    state: &DepositState,
) -> Option<RpcReimbursementStatus> {
    match state {
        DepositState::Spent {
            cooperative_payout_txid: Some(payout_txid),
            ..
        } => Some(RpcReimbursementStatus::Complete {
            claim_txid: None,
            payout_txid: *payout_txid,
            payout_kind: None,
        }),
        _ => None,
    }
}

/// Converts retained graph evidence into a reimbursement response.
pub(super) fn reimbursement_status(state: &GraphState) -> Result<RpcReimbursementStatus> {
    let status = match state {
        GraphState::Claimed { .. }
        | GraphState::Contested { .. }
        | GraphState::BridgeProofPosted { .. }
        | GraphState::BridgeProofTimedout { .. }
        | GraphState::CounterProofPosted { .. }
        | GraphState::AllNackd { .. }
        | GraphState::Acked { .. } => {
            let claim_txid = state
                .claim_txid()
                .context("active reimbursement has no claim")?;
            RpcReimbursementStatus::InProgress {
                claim_txid,
                phase: claim_phase(state)?,
            }
        }
        GraphState::Withdrawn {
            claim_txid,
            payout_txid,
            payout_kind,
            ..
        } => RpcReimbursementStatus::Complete {
            claim_txid: Some(*claim_txid),
            payout_txid: *payout_txid,
            payout_kind: Some(
                match payout_kind.context("completed claim has no payout kind")? {
                    PayoutKind::Uncontested => RpcPayoutKind::Uncontested,
                    PayoutKind::Contested => RpcPayoutKind::Contested,
                },
            ),
        },
        GraphState::Slashed {
            claim_txid,
            contest_txid,
            slash_txid,
            ..
        } => RpcReimbursementStatus::Slashed {
            claim_txid: *claim_txid,
            contest_txid: *contest_txid,
            slash_txid: *slash_txid,
        },
        GraphState::Aborted {
            claim_txid: Some(claim_txid),
            ..
        } => RpcReimbursementStatus::Aborted {
            claim_txid: *claim_txid,
        },
        _ => RpcReimbursementStatus::NotStarted,
    };
    Ok(status)
}

/// Converts an active graph using the same phase checks as reimbursement status.
pub(super) fn active_claim_from_state(
    operator: OperatorIdx,
    state: &GraphState,
) -> Result<Option<RpcActiveClaim>> {
    let fulfillment_txid = match state {
        GraphState::Claimed {
            fulfillment_txid, ..
        }
        | GraphState::Contested {
            fulfillment_txid, ..
        }
        | GraphState::BridgeProofPosted {
            fulfillment_txid, ..
        }
        | GraphState::BridgeProofTimedout {
            fulfillment_txid, ..
        }
        | GraphState::CounterProofPosted {
            fulfillment_txid, ..
        }
        | GraphState::AllNackd {
            fulfillment_txid, ..
        }
        | GraphState::Acked {
            fulfillment_txid, ..
        } => fulfillment_txid,
        _ => return Ok(None),
    };
    Ok(Some(RpcActiveClaim {
        operator,
        claim_txid: state
            .claim_txid()
            .context("active reimbursement has no claim")?,
        fulfilled: fulfillment_txid.is_some(),
        phase: claim_phase(state)?,
    }))
}

fn claim_phase(state: &GraphState) -> Result<RpcClaimPhase> {
    let contest_txid = match state {
        GraphState::Claimed { .. } => None,
        GraphState::Contested { graph_summary, .. }
        | GraphState::BridgeProofPosted { graph_summary, .. }
        | GraphState::BridgeProofTimedout { graph_summary, .. }
        | GraphState::CounterProofPosted { graph_summary, .. } => Some(graph_summary.contest),
        GraphState::AllNackd { contest_txid, .. } | GraphState::Acked { contest_txid, .. } => {
            Some(contest_txid.context("active challenge has no contest transaction ID")?)
        }
        _ => bail!("graph has no active claim phase"),
    };
    let payout_block_data = state.payout_block_data();
    let reason = match (
        payout_block_data.admin_block_txid.is_some(),
        payout_block_data.unstaking_block_txid.is_some(),
    ) {
        (true, false) => Some(RpcPayoutBlock::Admin),
        (false, true) => Some(RpcPayoutBlock::Unstaking),
        (true, true) => Some(RpcPayoutBlock::AdminAndUnstaking),
        (false, false) => None,
    };
    if let Some(reason) = reason {
        return Ok(RpcClaimPhase::Blocked {
            contest_txid,
            reason,
        });
    }
    let Some(contest_txid) = contest_txid else {
        return Ok(RpcClaimPhase::Claimed);
    };
    let phase = match state {
        GraphState::Contested { .. } => RpcClaimPhase::Contested { contest_txid },
        GraphState::BridgeProofPosted { .. } => RpcClaimPhase::BridgeProofPosted { contest_txid },
        GraphState::BridgeProofTimedout { .. } => {
            RpcClaimPhase::BridgeProofTimedout { contest_txid }
        }
        GraphState::CounterProofPosted { .. } => RpcClaimPhase::CounterProofPosted { contest_txid },
        GraphState::AllNackd { .. } => RpcClaimPhase::AllNackd { contest_txid },
        GraphState::Acked { .. } => RpcClaimPhase::Acked { contest_txid },
        _ => bail!("graph has no active claim phase"),
    };
    Ok(phase)
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
