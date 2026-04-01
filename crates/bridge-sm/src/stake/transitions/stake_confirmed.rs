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

                let is_my_stake = self.context.operator_idx() == self.context.operator_table().pov_idx();
                if is_my_stake {
                    return Err(SSMError::invalid_event(
                        self.state().clone(),
                        event.into(),
                        Some("own stake confirmed before all partial signatures collected".to_string())
                    ));
                }

                // it is possible to observe the confirmed stake transaction before observing all signatures, if the operator who owns the stake either does not broadcast their partial signature or broadcasts it too late. In this case, we still transition to the Confirmed state, but without the signatures.
                self.state = StakeState::Confirmed {
                    last_block_height: *last_block_height,
                    stake_data: stake_data.clone(),
                    stake_txid: expected_stake_txid,
                    signatures: Box::new(None),
                };

                Ok(SMOutput::new())
            },
            StakeState::UnstakingSigned {
                last_block_height,
                stake_data,
                expected_stake_txid,
                signatures,
                ..
            } => {
                if event.tx.compute_txid() != *expected_stake_txid {
                    return Err(SSMError::rejected(
                        self.state().clone(),
                        event.into(),
                        "Confirmed stake transaction does not match expected txid",
                    ));
                }

                self.state = StakeState::Confirmed {
                    last_block_height: *last_block_height,
                    stake_data: stake_data.clone(),
                    stake_txid: *expected_stake_txid,
                    signatures: Box::new(Some(*signatures.clone())),
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
