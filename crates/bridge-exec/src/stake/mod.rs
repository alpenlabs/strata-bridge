//! This module contains the executors for performing duties emitted by the Stake State Machine
//! transitions.

mod nag;
mod staking;
mod unstaking;
mod utils;

use std::sync::Arc;

use strata_bridge_primitives::covenant::{CovenantId, StakeKey};
use strata_bridge_sm::stake::{
    context::StakeSMCtx,
    duties::{NagDuty, StakeDuty},
};
use strata_bridge_tx_graph::musig_functor::StakeFunctor;
use tracing::info;

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

/// Executes the given stake duty.
pub async fn execute_stake_duty(
    cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    context: &StakeSMCtx,
    duty: &StakeDuty,
) -> Result<(), ExecutorError> {
    validate_stake_duty(context, duty, cfg.legacy_stake_covenant)?;
    info!(stake_key = %context.stake_key(), "executing covenant-qualified stake duty");
    match duty {
        StakeDuty::PublishStakeData { operator_idx } => {
            info!(%operator_idx, "executing StakeDuty::PublishStakeData");
            staking::publish_stake_data(&cfg, &output_handles, context.stake_key()).await
        }
        StakeDuty::PublishUnstakingNonces {
            operator_idx,
            graph_inpoints,
            graph_tweaks,
            sighashes,
            ordered_pubkeys,
        } => {
            info!(%operator_idx, "executing StakeDuty::PublishUnstakingNonces");
            staking::publish_unstaking_nonces(
                &output_handles,
                *operator_idx,
                **graph_inpoints,
                **graph_tweaks,
                **sighashes,
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
            staking::publish_stake(&cfg, &output_handles, tx).await
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

/// Rejects unsupported successor use of operator-only funding rows and wire messages.
fn validate_legacy_stake_key(key: StakeKey, legacy: CovenantId) -> Result<(), ExecutorError> {
    if key.covenant != legacy {
        return Err(ExecutorError::InvalidTxStructure(format!(
            "stake {key} requires covenant-qualified funding storage and wire messages"
        )));
    }
    Ok(())
}

fn validate_stake_duty(
    context: &StakeSMCtx,
    duty: &StakeDuty,
    legacy: CovenantId,
) -> Result<(), ExecutorError> {
    let invalid = |reason: &str| {
        ExecutorError::InvalidTxStructure(format!("stake {}: {reason}", context.stake_key()))
    };
    let Some(local) = context.pov_idx() else {
        return Err(invalid("observer cannot execute stake duties"));
    };
    let owner = match duty {
        StakeDuty::PublishStakeData { operator_idx }
        | StakeDuty::PublishStake { operator_idx, .. }
        | StakeDuty::PublishUnstakingNonces { operator_idx, .. }
        | StakeDuty::PublishUnstakingPartials { operator_idx, .. }
        | StakeDuty::Nag(
            NagDuty::NagUnstakingData { operator_idx, .. }
            | NagDuty::NagUnstakingNonces { operator_idx, .. }
            | NagDuty::NagUnstakingPartials { operator_idx, .. },
        ) => Some(*operator_idx),
        StakeDuty::PublishUnstakingIntent { .. } | StakeDuty::PublishUnstakingTx { .. } => None,
    };
    if owner.is_some_and(|owner| owner != context.operator_idx()) {
        return Err(invalid("duty owner does not match context"));
    }
    if matches!(
        duty,
        StakeDuty::PublishStakeData { .. }
            | StakeDuty::PublishStake { .. }
            | StakeDuty::PublishUnstakingIntent { .. }
            | StakeDuty::PublishUnstakingTx { .. }
    ) && local != context.operator_idx()
    {
        return Err(invalid("only the stake owner can publish this duty"));
    }
    if let StakeDuty::PublishUnstakingNonces {
        ordered_pubkeys, ..
    }
    | StakeDuty::PublishUnstakingPartials {
        ordered_pubkeys, ..
    } = duty
    {
        let expected: Vec<_> = context
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|key| key.x_only_public_key().0)
            .collect();
        if *ordered_pubkeys != expected {
            return Err(invalid("signing keys do not match covenant membership"));
        }
    }
    if matches!(
        duty,
        StakeDuty::PublishStakeData { .. }
            | StakeDuty::PublishUnstakingNonces { .. }
            | StakeDuty::PublishUnstakingPartials { .. }
            | StakeDuty::Nag(_)
    ) {
        validate_legacy_stake_key(context.stake_key(), legacy)?;
    }
    Ok(())
}

#[cfg(test)]
mod covenant_tests {
    use strata_bridge_sm::stake::context::StakeSMCtx;
    use strata_bridge_test_utils::{bitcoin::generate_tx, bridge_fixtures::test_operator_table};

    use super::*;

    #[test]
    fn executor_rejects_observers_and_wrong_stake_owners() {
        let table = test_operator_table(3, 0);
        let ctx = StakeSMCtx::new(0, table.clone(), 100);
        let key = ctx.stake_key();
        let publish = StakeDuty::PublishStakeData { operator_idx: 0 };
        assert!(validate_stake_duty(&ctx, &publish, key.covenant).is_ok());
        let wrong = StakeDuty::PublishStakeData { operator_idx: 1 };
        assert!(validate_stake_duty(&ctx, &wrong, key.covenant).is_err());
        let observer = StakeSMCtx::from_public(key, table.into_public(), None).unwrap();
        assert!(validate_stake_duty(&observer, &publish, key.covenant).is_err());
    }

    #[test]
    fn successor_cannot_reuse_legacy_funding_or_wire_identity() {
        let table = test_operator_table(3, 0);
        let historical = StakeSMCtx::new(0, table.clone(), 100);
        let successor = StakeSMCtx::new(0, table, 200);
        let duty = StakeDuty::PublishStakeData { operator_idx: 0 };
        assert!(validate_stake_duty(&successor, &duty, historical.stake_key().covenant).is_err());
        assert!(
            validate_legacy_stake_key(successor.stake_key(), historical.stake_key().covenant)
                .is_err()
        );
        // Already signed historical transactions retain their exact transaction context.
        let duty = StakeDuty::PublishUnstakingTx {
            signed_tx: generate_tx(1, 1),
        };
        assert!(validate_stake_duty(&historical, &duty, successor.stake_key().covenant).is_ok());
    }
}
