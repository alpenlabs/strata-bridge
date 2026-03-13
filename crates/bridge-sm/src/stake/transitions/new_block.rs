use std::sync::Arc;

use crate::{
    stake::{
        config::StakeSMCfg,
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::NewBlockEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`NewBlockEvent`].
    ///
    /// The machine updates to the latest height, rejecting old heights.
    /// In the [`StakeState::PreimageRevealed`] state, the machine emits the
    /// [`StakeDuty::PublishUnstakingTx`] duty if the unstaking timelock has matured.
    pub(crate) fn process_new_block(
        &mut self,
        cfg: Arc<StakeSMCfg>,
        event: NewBlockEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state_mut().last_processed_block_height_mut() {
            None => {
                return Err(SSMError::rejected(
                    self.state().clone(),
                    event.into(),
                    "Rejecting event because state machine is in a terminal state",
                ));
            }
            Some(last_block_height) if *last_block_height >= event.block_height => {
                return Err(SSMError::rejected(
                    self.state().clone(),
                    event.into(),
                    "Rejecting already processed block height",
                ));
            }
            Some(last_block_height) => *last_block_height = event.block_height,
        }

        if let StakeState::PreimageRevealed {
            stake_data,
            unstaking_intent_block_height,
            ..
        } = self.state()
            && event.block_height
                > *unstaking_intent_block_height + u64::from(cfg.unstaking_timelock.value())
        {
            return Ok(SMOutput::with_duties(vec![StakeDuty::PublishUnstakingTx {
                stake_data: stake_data.clone(),
            }]));
        }

        Ok(SMOutput::new())
    }
}
