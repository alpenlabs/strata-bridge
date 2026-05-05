use crate::{
    stake::{
        errors::{SSMError, SSMResult},
        events::SlashConfirmedEvent,
        machine::{SSMOutput, StakeSM},
        predicates::is_slash_tx,
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`SlashConfirmedEvent`].
    ///
    /// Transitions from [`StakeState::Confirmed`] or [`StakeState::PreimageRevealed`]
    /// to [`StakeState::Slashed`] when the observed transaction spends the stake output
    /// of the stake transaction and is not the legitimate unstaking transaction.
    pub(crate) fn process_slash_confirmed(
        &mut self,
        event: SlashConfirmedEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state() {
            StakeState::Created { .. }
            | StakeState::StakeGraphGenerated { .. }
            | StakeState::UnstakingNoncesCollected { .. }
            | StakeState::UnstakingSigned { .. } => Err(SSMError::invalid_event(
                self.state().clone(),
                event.into(),
                Some(format!(
                    "Slash confirmation is invalid before stake is confirmed: {}",
                    self.state()
                )),
            )),
            StakeState::Confirmed { summary, .. } => {
                if !is_slash_tx(summary, &event.tx) {
                    return Err(SSMError::rejected(
                        self.state().clone(),
                        event.into(),
                        "Transaction does not spend the stake output (not a slash transaction)",
                    ));
                }

                self.state = StakeState::Slashed {
                    summary: *summary,
                    slash_txid: event.tx.compute_txid(),
                    preimage: None,
                };

                Ok(SMOutput::new())
            }
            StakeState::PreimageRevealed {
                summary, preimage, ..
            } => {
                if !is_slash_tx(summary, &event.tx) {
                    return Err(SSMError::rejected(
                        self.state().clone(),
                        event.into(),
                        "Transaction does not spend the stake output (not a slash transaction)",
                    ));
                }

                self.state = StakeState::Slashed {
                    summary: *summary,
                    slash_txid: event.tx.compute_txid(),
                    preimage: Some(*preimage),
                };

                Ok(SMOutput::new())
            }
            StakeState::Slashed { .. } | StakeState::Unstaked { .. } => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                "Terminal state rejects all incoming events",
            )),
        }
    }
}
