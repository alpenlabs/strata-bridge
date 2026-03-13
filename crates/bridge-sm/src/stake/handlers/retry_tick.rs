use crate::{
    stake::{
        duties::StakeDuty,
        errors::SSMResult,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`RetryTickEvent`].
    ///
    /// Emits retriable duties for the current state.
    pub(crate) fn process_retry_tick(&self) -> SSMResult<SSMOutput> {
        let duties = match self.state() {
            StakeState::UnstakingSigned { .. } => vec![StakeDuty::PublishStake {
                operator_idx: self.context().operator_idx(),
            }],
            _ => Vec::new(),
        };

        Ok(SMOutput::with_duties(duties))
    }
}
