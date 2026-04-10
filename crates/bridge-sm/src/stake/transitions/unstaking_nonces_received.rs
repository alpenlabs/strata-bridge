use std::collections::BTreeMap;

use musig2::AggNonce;
use strata_bridge_tx_graph::{musig_functor::StakeFunctor, stake_graph::StakeGraph};

use crate::{
    stake::{
        duties::StakeDuty,
        errors::{SSMError, SSMResult},
        events::UnstakingNoncesReceivedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`UnstakingNoncesReceivedEvent`].
    ///
    /// While collecting nonces, the machine stays in [`StakeState::StakeGraphGenerated`].
    /// Once all operators have submitted their nonces, the machine transitions to
    /// [`StakeState::UnstakingNoncesCollected`] and emits
    /// [`StakeDuty::PublishUnstakingPartials`].
    pub(crate) fn process_unstaking_nonces_received(
        &mut self,
        event: UnstakingNoncesReceivedEvent,
    ) -> SSMResult<SSMOutput> {
        self.check_operator_idx(event.operator_idx, &event)?;

        let n_operators = self.context().operator_table().cardinality();

        match self.state_mut() {
            StakeState::StakeGraphGenerated {
                last_block_height,
                stake_data,
                summary,
                pub_nonces,
            } => {
                if pub_nonces.contains_key(&event.operator_idx) {
                    return Err(SSMError::duplicate(self.state().clone(), event.into()));
                }

                pub_nonces.insert(event.operator_idx, *event.pub_nonces);

                if pub_nonces.len() == n_operators {
                    let agg_nonces = StakeFunctor::sequence_functor(
                        pub_nonces.values().map(StakeFunctor::as_ref),
                    )
                    .map(AggNonce::sum)
                    .boxed();

                    let stake_data = stake_data.clone();
                    let stake_graph = StakeGraph::new(stake_data.clone());

                    self.state = StakeState::UnstakingNoncesCollected {
                        last_block_height: *last_block_height,
                        stake_data,
                        summary: *summary,
                        pub_nonces: pub_nonces.clone(),
                        agg_nonces: agg_nonces.clone(),
                        partial_signatures: BTreeMap::new(),
                    };

                    let graph_inpoints = stake_graph.musig_inpoints().boxed();
                    let (graph_tweaks, sighashes) = stake_graph
                        .musig_signing_info()
                        .map(|m| (m.tweak, m.sighash))
                        .unzip();
                    let graph_tweaks = graph_tweaks.boxed();
                    let sighashes = sighashes.boxed();

                    let ordered_pubkeys = self
                        .context()
                        .operator_table()
                        .btc_keys()
                        .into_iter()
                        .map(|k| k.x_only_public_key().0)
                        .collect();

                    Ok(SMOutput::with_duties(vec![
                        StakeDuty::PublishUnstakingPartials {
                            operator_idx: self.context().operator_idx(),
                            graph_inpoints,
                            graph_tweaks,
                            sighashes,
                            ordered_pubkeys,
                            agg_nonces,
                        },
                    ]))
                } else {
                    Ok(SMOutput::new())
                }
            }
            StakeState::UnstakingNoncesCollected { .. } => {
                Err(SSMError::duplicate(self.state().clone(), event.into()))
            }
            _ => Err(SSMError::rejected(
                self.state().clone(),
                event.into(),
                format!(
                    "Invalid state for collecting unstaking nonces: {}",
                    self.state()
                ),
            )),
        }
    }
}
