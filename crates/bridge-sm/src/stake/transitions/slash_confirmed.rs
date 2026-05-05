use crate::stake::{
    errors::SSMResult,
    events::SlashConfirmedEvent,
    machine::{SSMOutput, StakeSM},
};

impl StakeSM {
    /// Processes the [`SlashConfirmedEvent`].
    ///
    /// Transitions from [`StakeState::Confirmed`](crate::stake::state::StakeState::Confirmed) or
    /// [`StakeState::PreimageRevealed`](crate::stake::state::StakeState::PreimageRevealed) to
    /// [`StakeState::Slashed`](crate::stake::state::StakeState::Slashed) when the observed
    /// transaction spends the stake output of the stake transaction and is not the legitimate
    /// unstaking transaction.
    pub(crate) fn process_slash_confirmed(
        &mut self,
        _event: SlashConfirmedEvent,
    ) -> SSMResult<SSMOutput> {
        todo!("implement slash confirmation transition")
    }
}
