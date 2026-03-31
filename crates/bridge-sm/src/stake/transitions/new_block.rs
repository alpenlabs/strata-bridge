use std::sync::Arc;

use strata_bridge_tx_graph::{musig_functor::StakeFunctor, stake_graph::StakeGraph};

use crate::{
    stake::{
        config::StakeSMCfg,
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::NewBlockEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`NewBlockEvent`].
    ///
    /// The machine updates to the latest height, rejecting old heights.
    /// In the [`StakeState::PreimageRevealed`] state, the machine emits the
    /// [`StakeDuty::PublishUnstakingTx`] duty if the unstaking timelock has matured.
    pub(crate) fn process_new_block(
        &mut self,
        cfg: Arc<StakeSMCfg>,
        event: NewBlockEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state_mut().last_processed_block_height_mut() {
            None => {
                return Err(SSMError::rejected(
                    self.state().clone(),
                    event.into(),
                    "Rejecting event because state machine is in a terminal state",
                ));
            }
            Some(last_block_height) if *last_block_height >= event.block_height => {
                return Err(SSMError::rejected(
                    self.state().clone(),
                    event.into(),
                    "Rejecting already processed block height",
                ));
            }
            Some(last_block_height) => *last_block_height = event.block_height,
        }

        if let StakeState::PreimageRevealed {
            stake_data,
            unstaking_intent_block_height,
            signatures,
            ..
        } = self.state()
            && event.block_height
                > *unstaking_intent_block_height
                    + u64::from(cfg.protocol_params.game_timelock.value())
        {
            let stake_graph = StakeGraph::new(stake_data.clone());
            let unstaking_sig_functor = StakeFunctor::unpack(signatures.to_vec())
                .expect("signatures already in state must be valid");
            let unstaking_tx = stake_graph
                .unstaking
                .finalize(unstaking_sig_functor.unstaking);

            return Ok(SMOutput::with_duties(vec![StakeDuty::PublishUnstakingTx {
                signed_tx: unstaking_tx,
            }]));
        }

        Ok(SMOutput::new())
    }
}
