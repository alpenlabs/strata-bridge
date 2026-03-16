use std::collections::BTreeMap;

use crate::{
    stake::{
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::StakeDataReceivedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`StakeDataReceivedEvent`].
    ///
    /// The machine transitions from [`StakeState::Created`] to [`StakeState::StakeGraphGenerated`]
    /// and emits a [`StakeDuty::PublishUnstakingNonces`] duty so operators can start the
    /// presigning flow.
    pub(crate) fn process_stake_data(
        &mut self,
        event: StakeDataReceivedEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state() {
            StakeState::Created {
                last_block_height, ..
            } => {
                let stake_data = event.stake_data;

                self.state = StakeState::StakeGraphGenerated {
                    last_block_height: *last_block_height,
                    stake_data: stake_data.clone(),
                    pub_nonces: BTreeMap::new(),
                };

                Ok(SMOutput::with_duties(vec![
                    StakeDuty::PublishUnstakingNonces { stake_data },
                ]))
            }
            StakeState::StakeGraphGenerated { .. } => {
                Err(SSMError::duplicate(self.state().clone(), event.into()))
            }
            _ => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                format!("Invalid state for receiving stake data: {}", self.state()),
            )),
        }
    }
}
