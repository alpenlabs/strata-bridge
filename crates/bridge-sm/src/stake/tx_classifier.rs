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
            StakeState::UnstakingNoncesCollected { .. } => None,

            StakeState::UnstakingSigned {
                expected_stake_txid,
                ..
            } if txid == *expected_stake_txid => {
                Some(StakeConfirmedEvent { tx: tx.clone() }.into())
            }
            StakeState::UnstakingSigned { .. } => None,

            StakeState::Confirmed { stake_data, .. } => {
                let summary = StakeGraph::new(stake_data.clone()).summarize();

                (txid == summary.unstaking_intent).then(|| {
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
