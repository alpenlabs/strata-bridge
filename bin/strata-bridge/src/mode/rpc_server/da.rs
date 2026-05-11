//! Helpers that derive DA RPC responses from recovered state-machine state.

use bitcoin::secp256k1::schnorr;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_rpc::types::{RpcStakeAggregateSignatures, RpcStakeData};
use strata_bridge_sm::stake::{
    config::StakeSMCfg,
    context::{MinimumStakeData, StakeSMCtx},
    state::StakeState,
};
use strata_bridge_tx_graph::musig_functor::StakeFunctor;

pub(super) fn stake_data_response(
    context: &StakeSMCtx,
    state: &StakeState,
    stake_cfg: &StakeSMCfg,
) -> Option<RpcStakeData> {
    let stake_data = minimum_stake_data_from_state(state)?;
    let full_stake_data = stake_data.expand(*stake_cfg, context);

    Some(RpcStakeData {
        context: context.clone(),
        protocol: full_stake_data.protocol,
        setup: full_stake_data.setup,
    })
}

pub(super) fn stake_aggregate_signatures_response(
    operator_idx: OperatorIdx,
    state: &StakeState,
) -> Option<RpcStakeAggregateSignatures> {
    let signatures = stake_aggregate_signatures_from_state(state)?;

    Some(RpcStakeAggregateSignatures {
        operator_idx,
        signatures: (*signatures).pack().to_vec(),
    })
}

const fn minimum_stake_data_from_state(state: &StakeState) -> Option<&MinimumStakeData> {
    match state {
        StakeState::StakeGraphGenerated { stake_data, .. }
        | StakeState::UnstakingNoncesCollected { stake_data, .. }
        | StakeState::UnstakingSigned { stake_data, .. }
        | StakeState::Confirmed { stake_data, .. }
        | StakeState::PreimageRevealed { stake_data, .. } => Some(stake_data),
        _ => None,
    }
}

fn stake_aggregate_signatures_from_state(
    state: &StakeState,
) -> Option<&StakeFunctor<schnorr::Signature>> {
    match state {
        StakeState::UnstakingSigned { signatures, .. } => Some(signatures.as_ref()),
        StakeState::Confirmed { signatures, .. }
        | StakeState::PreimageRevealed { signatures, .. } => signatures.as_ref().as_ref(),
        _ => None,
    }
}
