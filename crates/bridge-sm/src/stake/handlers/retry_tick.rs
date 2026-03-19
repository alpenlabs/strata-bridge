use strata_bridge_tx_graph::stake_graph::StakeGraph;

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
            StakeState::UnstakingSigned { stake_data, .. } => {
                let stake_graph = StakeGraph::new(stake_data.clone());
                vec![StakeDuty::PublishStake {
                    tx: stake_graph.stake.as_ref().clone(),
                }]
            }
            _ => Vec::new(),
        };

        Ok(SMOutput::with_duties(duties))
    }
}
