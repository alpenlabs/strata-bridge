use std::{array, collections::BTreeMap};

use musig2::AggNonce;

use crate::{
    stake::{
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::UnstakingNoncesReceivedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`UnstakingNoncesReceivedEvent`].
    ///
    /// While collecting nonces, the machine stays in [`StakeState::StakeGraphGenerated`].
    /// Once all operators have submitted their nonces, the machine transitions to
    /// [`StakeState::UnstakingNoncesCollected`] and emits
    /// [`StakeDuty::PublishUnstakingPartials`].
    pub(crate) fn process_unstaking_nonces_received(
        &mut self,
        event: UnstakingNoncesReceivedEvent,
    ) -> SSMResult<SSMOutput> {
        self.check_operator_idx(event.operator_idx, &event)?;

        let n_operators = self.context().operator_table().cardinality();

        match self.state_mut() {
            StakeState::StakeGraphGenerated {
                last_block_height,
                stake_data,
                pub_nonces,
            } => {
                if pub_nonces.contains_key(&event.operator_idx) {
                    return Err(SSMError::duplicate(self.state().clone(), event.into()));
                }

                pub_nonces.insert(event.operator_idx, event.pub_nonces);

                if pub_nonces.len() == n_operators {
                    let agg_nonces = Box::new(array::from_fn(|txin_idx| {
                        AggNonce::sum(pub_nonces.values().map(|nonces| nonces[txin_idx].clone()))
                    }));
                    let stake_data = stake_data.clone();

                    self.state = StakeState::UnstakingNoncesCollected {
                        last_block_height: *last_block_height,
                        stake_data: stake_data.clone(),
                        pub_nonces: pub_nonces.clone(),
                        agg_nonces: agg_nonces.clone(),
                        partial_signatures: BTreeMap::new(),
                    };

                    Ok(SMOutput::with_duties(vec![
                        StakeDuty::PublishUnstakingPartials {
                            stake_data,
                            agg_nonces,
                        },
                    ]))
                } else {
                    Ok(SMOutput::new())
                }
            }
            StakeState::UnstakingNoncesCollected { .. } => {
                Err(SSMError::duplicate(self.state().clone(), event.into()))
            }
            _ => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                format!(
                    "Invalid state for collecting unstaking nonces: {}",
                    self.state()
                ),
            )),
        }
    }
}
