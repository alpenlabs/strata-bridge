//! This module contains the executors for performing duties emitted by the Stake State Machine
//! transitions.

mod nag;
mod staking;
mod unstaking;
mod utils;

use std::sync::Arc;

use strata_bridge_sm::stake::duties::StakeDuty;
use strata_bridge_tx_graph::musig_functor::StakeFunctor;
use tracing::info;

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

/// Executes the given stake duty.
pub async fn execute_stake_duty(
    cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    duty: &StakeDuty,
) -> Result<(), ExecutorError> {
    match duty {
        StakeDuty::PublishStakeData { operator_idx } => {
            info!(%operator_idx, "executing StakeDuty::PublishStakeData");
            staking::publish_stake_data(&cfg, &output_handles, *operator_idx).await
        }
        StakeDuty::PublishUnstakingNonces {
            operator_idx,
            graph_inpoints,
            graph_tweaks,
            ordered_pubkeys,
        } => {
            info!(%operator_idx, "executing StakeDuty::PublishUnstakingNonces");
            staking::publish_unstaking_nonces(
                &output_handles,
                *operator_idx,
                **graph_inpoints,
                **graph_tweaks,
                ordered_pubkeys.clone(),
            )
            .await
        }
        StakeDuty::PublishUnstakingPartials {
            operator_idx,
            graph_inpoints,
            graph_tweaks,
            sighashes,
            ordered_pubkeys,
            agg_nonces,
        } => {
            info!(%operator_idx, "executing StakeDuty::PublishUnstakingPartials");
            staking::publish_unstaking_partials(
                &output_handles,
                *operator_idx,
                **graph_inpoints,
                **graph_tweaks,
                **sighashes,
                StakeFunctor::clone(agg_nonces),
                ordered_pubkeys.clone(),
            )
            .await
        }
        StakeDuty::PublishStake { operator_idx, tx } => {
            info!(%operator_idx, stake_txid=%tx.compute_txid(), "executing StakeDuty::PublishStake");
            staking::publish_stake(&cfg, &output_handles, *operator_idx, tx).await
        }
        StakeDuty::PublishUnstakingIntent {
            unsigned_tx,
            stake_funds,
            n_of_n_signature,
        } => {
            info!(%stake_funds, "executing StakeDuty::PublishUnstakingIntent");
            unstaking::publish_unstaking_intent(
                &output_handles,
                *stake_funds,
                (**unsigned_tx).clone(),
                n_of_n_signature,
            )
            .await
        }
        StakeDuty::PublishUnstakingTx { signed_tx } => {
            info!(unstaking_txid=%signed_tx.compute_txid(), "executing StakeDuty::PublishUnstakingTx");
            unstaking::publish_unstaking_tx(&output_handles, signed_tx).await
        }
        StakeDuty::Nag(nag_duty) => {
            info!(?nag_duty, "executing StakeDuty::Nag");
            nag::execute_nag_duty(&output_handles, nag_duty).await
        }
    }
}
