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
            StakeState::Created { .. }
            | StakeState::StakeGraphGenerated { .. }
            | StakeState::UnstakingNoncesCollected { .. }
            | StakeState::UnstakingSigned { .. }
            | StakeState::Confirmed { .. } => Err(SSMError::invalid_event(
                self.state().clone(),
                event.into(),
                Some(format!(
                    "Unstaking confirmation is invalid before preimage revelation: {}",
                    self.state()
                )),
            )),
            StakeState::PreimageRevealed {
                preimage, summary, ..
            } => {
                if event.tx.compute_txid() != summary.unstaking {
                    return Err(SSMError::rejected(
                        self.state().clone(),
                        event.into(),
                        "The observed unstaking transaction does not match the expected TXID",
                    ));
                }

                self.state = StakeState::Unstaked {
                    preimage: *preimage,
                    unstaking_txid: summary.unstaking,
                };

                Ok(SMOutput::new())
            }
            StakeState::Unstaked { .. } => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                "Terminal state rejects all incoming events",
            )),
        }
    }
}
