use crate::{
    stake::{
        errors::{SSMError, SSMResult},
        events::UnstakingConfirmedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`UnstakingConfirmedEvent`].
    ///
    /// The machine transitions from [`StakeState::PreimageRevealed`] to [`StakeState::Unstaked`]
    /// when the confirmed transaction matches the expected unstaking TXID.
    pub(crate) fn process_unstaking_confirmed(
        &mut self,
        event: UnstakingConfirmedEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state() {
            StakeState::PreimageRevealed {
                preimage,
                expected_unstaking_txid,
                ..
            } => {
                if event.tx.compute_txid() != *expected_unstaking_txid {
                    return Err(SSMError::rejected(
                        self.state().clone(),
                        event.into(),
                        "The observed unstaking transaction does not match the expected TXID",
                    ));
                }

                self.state = StakeState::Unstaked {
                    preimage: *preimage,
                    unstaking_txid: *expected_unstaking_txid,
                };

                Ok(SMOutput::new())
            }
            StakeState::Unstaked { .. } => {
                Err(SSMError::duplicate(self.state.clone(), event.into()))
            }
            _ => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                format!("Invalid state for unstaking confirmation: {}", self.state()),
            )),
        }
    }
}
