use crate::{
    stake::{
        errors::SSMResult,
        events::StakeConfirmedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`StakeConfirmedEvent`].
    ///
    /// The machine transitions from [`StakeState::UnstakingSigned`] to [`StakeState::Confirmed`]
    /// when the confirmed stake transaction matches the expected ID.
    ///
    /// In all other states, this event is ignored.
    pub(crate) fn process_stake_confirmed(
        &mut self,
        event: StakeConfirmedEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state() {
            StakeState::UnstakingSigned {
                last_block_height,
                stake_data,
                expected_stake_txid,
                ..
            } => {
                if event.tx.compute_txid() != *expected_stake_txid {
                    return Err(crate::stake::errors::SSMError::rejected(
                        self.state().clone(),
                        event.into(),
                        "Confirmed stake transaction does not match expected txid",
                    ));
                }

                self.state = StakeState::Confirmed {
                    last_block_height: *last_block_height,
                    stake_data: stake_data.clone(),
                    stake_txid: *expected_stake_txid,
                };

                Ok(SMOutput::new())
            }
            _ => Ok(SMOutput::new()),
        }
    }
}
