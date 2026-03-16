use strata_bridge_tx_graph::stake_graph::StakeGraph;

use crate::{
    stake::{
        errors::{SSMError, SSMResult},
        events::PreimageRevealedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`PreimageRevealedEvent`].
    ///
    /// The machine transitions from [`StakeState::Confirmed`] to [`StakeState::PreimageRevealed`]
    /// when the observed unstaking intent transaction matches the expected TXID.
    /// The preimage is extracted from the witness stack of the transaction.
    pub(crate) fn process_preimage_revealed(
        &mut self,
        event: PreimageRevealedEvent,
    ) -> SSMResult<SSMOutput> {
        match self.state() {
            StakeState::Confirmed {
                last_block_height: _,
                stake_data,
                stake_txid: _,
            } => {
                let summary = StakeGraph::new(stake_data.clone()).summarize();

                if event.tx.compute_txid() != summary.unstaking_intent {
                    return Err(SSMError::invalid_event(
                        self.state().clone(),
                        event.into(),
                        Some("The observed unstaking intent transaction does not match the expected TXID".to_string()),
                    ));
                }

                // NOTE: (@uncomputable) Because we verified the TXID, we can safely assume
                // that the given transaction has the exact structure of the unstaking intent
                // transaction. Forging a transaction with the same TXID but with a
                // different structure is a cryptographically hard problem.
                //
                // This means we know that event.tx has a first input,
                // but we don't have any guarantees about its witness.
                let Some(preimage): Option<[u8; 32]> = event
                    .tx
                    .input
                    .first()
                    .and_then(|txin| txin.witness.iter().next())
                    .and_then(|stack_item| stack_item.try_into().ok())
                else {
                    return Err(SSMError::invalid_event(
                        self.state().clone(),
                        event.into(),
                        Some("The observed unstaking intent transaction is missing valid witness data".to_string()),
                    ));
                };

                self.state = StakeState::PreimageRevealed {
                    last_block_height: event.block_height,
                    stake_data: stake_data.clone(),
                    preimage,
                    unstaking_intent_block_height: event.block_height,
                    expected_unstaking_txid: summary.unstaking,
                };

                Ok(SMOutput::new())
            }
            StakeState::PreimageRevealed { .. } => {
                Err(SSMError::duplicate(self.state().clone(), event.into()))
            }
            _ => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                format!("Invalid state for preimage revelation: {}", self.state()),
            )),
        }
    }
}
