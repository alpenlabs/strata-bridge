//! This module contains the executors for performing duties emitted by the Stake State Machine
//! transitions.

mod nag;
mod staking;
mod unstaking;
mod utils;

use std::sync::Arc;

use strata_bridge_sm::stake::duties::StakeDuty;

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

/// Executes the given stake duty.
pub async fn execute_stake_duty(
    cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    duty: &StakeDuty,
) -> Result<(), ExecutorError> {
    match duty {
        StakeDuty::PublishStakeData { operator_idx } => {
            staking::publish_stake_data(&cfg, &output_handles, *operator_idx).await
        }
        StakeDuty::PublishUnstakingNonces { stake_data } => {
            staking::publish_unstaking_nonces(&cfg, &output_handles, stake_data).await
        }
        StakeDuty::PublishUnstakingPartials {
            stake_data,
            agg_nonces,
        } => {
            staking::publish_unstaking_partials(&cfg, &output_handles, stake_data, agg_nonces).await
        }
        StakeDuty::PublishStake { tx } => staking::publish_stake(&output_handles, tx).await,
        StakeDuty::PublishUnstakingIntent {
            unsigned_tx,
            stake_funds,
            n_of_n_signature,
        } => {
            unstaking::publish_unstaking_intent(
                &output_handles,
                *stake_funds,
                (**unsigned_tx).clone(),
                n_of_n_signature,
            )
            .await
        }
        StakeDuty::PublishUnstakingTx { signed_tx } => {
            unstaking::publish_unstaking_tx(&output_handles, signed_tx).await
        }
        StakeDuty::Nag(nag_duty) => nag::execute_nag_duty(&cfg, &output_handles, nag_duty).await,
    }
}
