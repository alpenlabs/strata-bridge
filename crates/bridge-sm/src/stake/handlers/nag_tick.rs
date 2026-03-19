use std::collections::BTreeSet;

use crate::{
    stake::{
        duties::{NagDuty, StakeDuty},
        errors::SSMResult,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`NagTickEvent`].
    ///
    /// Emits nag duties for operators who haven't submitted their expected data
    /// for the current state.
    pub(crate) fn process_nag_tick(&self) -> SSMResult<SSMOutput> {
        let expected_ids = self.context().operator_table().operator_idxs();
        let present_ids: BTreeSet<_> = match self.state() {
            StakeState::Created { .. } => BTreeSet::from([self.context().operator_idx()]),
            StakeState::StakeGraphGenerated { pub_nonces, .. } => {
                pub_nonces.keys().copied().collect()
            }
            StakeState::UnstakingNoncesCollected {
                partial_signatures, ..
            } => partial_signatures.keys().copied().collect(),
            _ => BTreeSet::new(),
        };

        let duties = match self.state() {
            StakeState::Created { .. } => vec![StakeDuty::Nag(NagDuty::NagStakeData {
                operator_idx: self.context().operator_idx(),
            })],
            StakeState::StakeGraphGenerated { .. } => expected_ids
                .difference(&present_ids)
                .map(|&operator_idx| StakeDuty::Nag(NagDuty::NagUnstakingNonces { operator_idx }))
                .collect(),
            StakeState::UnstakingNoncesCollected { .. } => expected_ids
                .difference(&present_ids)
                .map(|&operator_idx| StakeDuty::Nag(NagDuty::NagUnstakingPartials { operator_idx }))
                .collect(),
            _ => Vec::new(),
        };

        Ok(SMOutput::with_duties(duties))
    }
}
