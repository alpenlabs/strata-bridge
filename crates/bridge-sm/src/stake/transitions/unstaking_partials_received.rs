use std::array;

use musig2::{aggregate_partial_signatures, verify_partial};
use strata_bridge_primitives::key_agg::create_agg_ctx;
use strata_bridge_tx_graph::stake_graph::StakeGraph;

use crate::{
    stake::{
        errors::{SSMError, SSMResult},
        events::UnstakingPartialsReceivedEvent,
        machine::{SSMOutput, StakeSM},
        state::StakeState,
    },
    state_machine::SMOutput,
};

impl StakeSM {
    /// Processes the [`UnstakingPartialsReceivedEvent`].
    ///
    /// While collecting partial signatures, the machine stays in
    /// [`StakeState::UnstakingNoncesCollected`]. Once all operators have submitted valid
    /// partial signatures, the machine transitions to [`StakeState::UnstakingSigned`].
    pub(crate) fn process_unstaking_partials_received(
        &mut self,
        event: UnstakingPartialsReceivedEvent,
    ) -> SSMResult<SSMOutput> {
        self.check_operator_idx(event.operator_idx, &event)?;

        let n_operators = self.context().operator_table().cardinality();
        let operator_pubkeys: Vec<_> = self
            .context()
            .operator_table()
            .btc_keys()
            .into_iter()
            .collect();
        let current_operator_pubkey = self
            .context()
            .operator_table()
            .idx_to_btc_key(&event.operator_idx)
            .expect("operator index has been validated above");

        match self.state_mut() {
            StakeState::UnstakingNoncesCollected {
                last_block_height,
                stake_data,
                pub_nonces,
                agg_nonces,
                partial_signatures,
            } => {
                if partial_signatures.contains_key(&event.operator_idx) {
                    return Err(SSMError::duplicate(
                        self.state.clone(),
                        event.clone().into(),
                    ));
                }

                let operator_pub_nonces = pub_nonces
                    .get(&event.operator_idx)
                    .expect("operator index has been validated above");
                let stake_graph = StakeGraph::new(stake_data.clone());
                let signing_infos = stake_graph.musig_signing_info().pack();

                for (txin_idx, (((signing_info, partial_sig), agg_nonce), pub_nonce)) in
                    signing_infos
                        .iter()
                        .zip(event.partial_signatures.iter().copied())
                        .zip(agg_nonces.iter())
                        .zip(operator_pub_nonces.iter())
                        .enumerate()
                {
                    let key_agg_ctx =
                        create_agg_ctx(operator_pubkeys.iter().copied(), &signing_info.tweak)
                            .expect("must be able to create key aggregation context");

                    if verify_partial(
                        &key_agg_ctx,
                        partial_sig,
                        agg_nonce,
                        current_operator_pubkey,
                        pub_nonce,
                        signing_info.sighash.as_ref(),
                    )
                    .is_err()
                    {
                        return Err(SSMError::rejected(
                            self.state.clone(),
                            event.clone().into(),
                            format!(
                                "Partial signature verification failed for operator {} at index {}",
                                event.operator_idx, txin_idx
                            ),
                        ));
                    }
                }

                partial_signatures.insert(event.operator_idx, event.partial_signatures);

                if partial_signatures.len() == n_operators {
                    let signatures = Box::new(array::from_fn(|txin_idx| {
                        let signing_info = &signing_infos[txin_idx];
                        let key_agg_ctx =
                            create_agg_ctx(operator_pubkeys.iter().copied(), &signing_info.tweak)
                                .expect("must be able to create key aggregation context");

                        aggregate_partial_signatures(
                            &key_agg_ctx,
                            &agg_nonces[txin_idx],
                            partial_signatures
                                .values()
                                .map(|partial_sigs_single_operator| {
                                    partial_sigs_single_operator[txin_idx]
                                }),
                            signing_info.sighash.as_ref(),
                        )
                        .expect("partial signatures have been checked to be valid")
                    }));

                    self.state = StakeState::UnstakingSigned {
                        last_block_height: *last_block_height,
                        stake_data: stake_data.clone(),
                        expected_stake_txid: stake_graph.stake.as_ref().compute_txid(),
                        signatures,
                    };
                }

                Ok(SMOutput::new())
            }
            StakeState::UnstakingSigned { .. } => Err(SSMError::duplicate(
                self.state.clone(),
                event.clone().into(),
            )),
            _ => Err(SSMError::rejected(
                self.state.clone(),
                event.into(),
                format!(
                    "Invalid state for collecting unstaking partials: {}",
                    self.state()
                ),
            )),
        }
    }
}
