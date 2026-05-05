//! [`TxClassifier`] implementation for [`StakeSM`].

use bitcoin::Transaction;
use strata_bridge_primitives::types::BitcoinBlockHeight;

use crate::{
    stake::{
        events::{
            PreimageRevealedEvent, SlashConfirmedEvent, StakeConfirmedEvent,
            UnstakingConfirmedEvent,
        },
        machine::StakeSM,
        predicates::is_slash_tx,
        state::StakeState,
    },
    tx_classifier::TxClassifier,
};

impl TxClassifier for StakeSM {
    fn classify_tx(
        &self,
        _config: &Self::Config,
        tx: &Transaction,
        height: BitcoinBlockHeight,
    ) -> Option<Self::Event> {
        let txid = tx.compute_txid();

        match self.state() {
            StakeState::Created { .. } => None,
            StakeState::StakeGraphGenerated { .. } => None,
            // NOTE: (@uncomputable) When an operator submits its partial last and it already has
            // partials from all other operators, then it will publish the stake transaction.
            // If the other operators see the stake transaction on chain before receiving the
            // partial, then they will still be in the UnstakingNoncesCollected state.
            // We have to handle this case here, even though it is unlikely.
            StakeState::UnstakingNoncesCollected { summary, .. }
            | StakeState::UnstakingSigned { summary, .. } => {
                (txid == summary.stake).then(|| StakeConfirmedEvent { tx: tx.clone() }.into())
            }
            StakeState::Confirmed { summary, .. } if txid == summary.unstaking_intent => Some(
                PreimageRevealedEvent {
                    tx: tx.clone(),
                    block_height: height,
                }
                .into(),
            ),
            StakeState::Confirmed { summary, .. } if is_slash_tx(summary, tx) => {
                Some(SlashConfirmedEvent { tx: tx.clone() }.into())
            }
            StakeState::PreimageRevealed { summary, .. } if txid == summary.unstaking => {
                Some(UnstakingConfirmedEvent { tx: tx.clone() }.into())
            }
            StakeState::PreimageRevealed { summary, .. } if is_slash_tx(summary, tx) => {
                Some(SlashConfirmedEvent { tx: tx.clone() }.into())
            }

            StakeState::Confirmed { .. }
            | StakeState::PreimageRevealed { .. }
            | StakeState::Unstaked { .. }
            | StakeState::Slashed { .. } => None,
        }
    }
}
