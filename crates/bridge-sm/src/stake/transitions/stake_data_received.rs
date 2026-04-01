use std::collections::BTreeMap;

use strata_bridge_tx_graph::stake_graph::{StakeData, StakeGraph};

use crate::{
    stake::{
        config::StakeSMCfg,
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::StakeDataReceivedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`StakeDataReceivedEvent`].
    ///
    /// The machine transitions from [`StakeState::Created`] to [`StakeState::StakeGraphGenerated`]
    /// and emits a [`StakeDuty::PublishUnstakingNonces`] duty so operators can start the
    /// presigning flow.
    pub(crate) fn process_stake_data(
        &mut self,
        cfg: &StakeSMCfg,
        event: StakeDataReceivedEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state() {
            StakeState::Created {
                last_block_height, ..
            } => {
                let StakeDataReceivedEvent {
                    stake_funds,
                    unstaking_image,
                    unstaking_output_desc,
                } = event;
                let setup = self.context().generate_setup_params(
                    stake_funds,
                    unstaking_image,
                    unstaking_output_desc,
                );
                let stake_data = StakeData {
                    setup,
                    protocol: cfg.protocol_params,
                };

                self.state = StakeState::StakeGraphGenerated {
                    last_block_height: *last_block_height,
                    stake_data: stake_data.clone(),
                    pub_nonces: BTreeMap::new(),
                };

                let stake_graph = StakeGraph::new(stake_data);
                let graph_inpoints = stake_graph
                    .musig_inpoints()
                    .pack()
                    .try_into()
                    .expect("number of musig inputs is correct by construction");

                let graph_tweaks = stake_graph
                    .musig_signing_info()
                    .pack()
                    .iter()
                    .map(|m| m.tweak)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("number of musig inputs is correct by construction");

                let ordered_pubkeys = self
                    .context()
                    .operator_table()
                    .btc_keys()
                    .into_iter()
                    .map(|k| k.x_only_public_key().0)
                    .collect();

                Ok(SMOutput::with_duties(vec![
                    StakeDuty::PublishUnstakingNonces {
                        operator_idx: self.context().operator_idx(),
                        graph_inpoints,
                        graph_tweaks,
                        ordered_pubkeys,
                    },
                ]))
            }
            StakeState::StakeGraphGenerated { .. } => {
                Err(SSMError::duplicate(self.state().clone(), event.into()))
            }
            _ => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                format!("Invalid state for receiving stake data: {}", self.state()),
            )),
        }
    }
}
