//! [`TxClassifier`] implementation for [`StakeSM`].

use bitcoin::Transaction;
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_bridge_tx_graph::stake_graph::StakeGraph;

use crate::{
    stake::{
        events::{PreimageRevealedEvent, StakeConfirmedEvent, UnstakingConfirmedEvent},
        machine::StakeSM,
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
            StakeState::UnstakingNoncesCollected { stake_data, .. }
            | StakeState::UnstakingSigned { stake_data, .. } => {
                let stake_txid = StakeGraph::new(stake_data.clone())
                    .stake
                    .as_ref()
                    .compute_txid();

                (txid == stake_txid).then(|| StakeConfirmedEvent { tx: tx.clone() }.into())
            }
            StakeState::Confirmed { stake_data, .. } => {
                let unstaking_intent_txid = StakeGraph::new(stake_data.clone())
                    .unstaking_intent
                    .as_ref()
                    .compute_txid();

                (txid == unstaking_intent_txid).then(|| {
                    PreimageRevealedEvent {
                        tx: tx.clone(),
                        block_height: height,
                    }
                    .into()
                })
            }
            StakeState::PreimageRevealed {
                expected_unstaking_txid,
                ..
            } if txid == *expected_unstaking_txid => {
                Some(UnstakingConfirmedEvent { tx: tx.clone() }.into())
            }

            StakeState::PreimageRevealed { .. } | StakeState::Unstaked { .. } => None,
        }
    }
}
