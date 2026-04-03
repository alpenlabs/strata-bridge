use strata_bridge_tx_graph::stake_graph::StakeGraph;

use crate::{
    stake::{
        errors::{SSMError, SSMResult},
        events::StakeConfirmedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`StakeConfirmedEvent`].
    ///
    /// The machine transitions from [`StakeState::UnstakingNoncesCollected`] or
    /// [`StakeState::UnstakingSigned`] to [`StakeState::Confirmed`] when the confirmed
    /// stake transaction matches the expected ID.
    pub(crate) fn process_stake_confirmed(
        &mut self,
        event: StakeConfirmedEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state() {
            StakeState::UnstakingNoncesCollected {
                last_block_height,
                stake_data,
                ..
            }
            | StakeState::UnstakingSigned {
                last_block_height,
                stake_data,
                ..
            } => {
                let expected_stake_txid = StakeGraph::new(stake_data.clone())
                    .stake
                    .as_ref()
                    .compute_txid();

                if event.tx.compute_txid() != expected_stake_txid {
                    return Err(SSMError::rejected(
                        self.state().clone(),
                        event.into(),
                        "Confirmed stake transaction does not match expected txid",
                    ));
                }

                self.state = StakeState::Confirmed {
                    last_block_height: *last_block_height,
                    stake_data: stake_data.clone(),
                };

                Ok(SMOutput::new())
            }
            StakeState::Confirmed { .. } => {
                Err(SSMError::duplicate(self.state.clone(), event.into()))
            }
            StakeState::PreimageRevealed { .. } | StakeState::Unstaked { .. } => Err(SSMError::invalid_event(
                self.state().clone(),
                event.into(),
                Some("Stake confirmation is invalid after unstaking (intent) transactions have been observed".to_string()
            ))),
            _ => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                format!("Invalid state for stake confirmation: {}", self.state()),
            )),
        }
    }
}
