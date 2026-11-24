use std::{collections::BTreeMap, sync::Arc};

use bitcoin::Transaction;
use strata_bridge_tx_graph::{
    game_graph::{DepositParams, GameConnectors, GameGraphSummary},
    transactions::prelude::{CounterproofNackData, CounterproofNackTx},
};
use strata_mosaic_client_api::types::{COUNTERPROOF_N_DATA, CompletedSignatures, Signature};
use tracing::warn;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::CounterProofConfirmedEvent,
    machine::{GSMOutput, GraphSM},
    state::{CounterproofData, GraphState},
};

impl GraphSM {
    /// Processes the event where a counterproof transaction has been confirmed on-chain.
    pub(crate) fn process_counterproof(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        event: CounterProofConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        self.check_operator_idx(event.counterprover_idx, &event)?;

        match self.state.clone() {
            GraphState::Contested {
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                let (nack_duties, completed_signatures) =
                    self.validate_counterproof_and_nack(&cfg, &event, &graph_data, &graph_summary)?;

                let mut counterproofs_and_confs = BTreeMap::new();
                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    CounterproofData {
                        txid: event.tx.compute_txid(),
                        conf_height: event.counterproof_block_height,
                        completed_signatures,
                    },
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.counterproof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_bridge_proof: None,
                    counterproofs_and_confs,
                    counterproof_nacks: BTreeMap::new(),
                    stake_spent,
                    payout_connector_spent,
                };

                Ok(GSMOutput::with_duties(nack_duties))
            }
            GraphState::BridgeProofPosted {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                proof,
                bridge_proof_tx,
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                let (nack_duties, completed_signatures) =
                    self.validate_counterproof_and_nack(&cfg, &event, &graph_data, &graph_summary)?;

                let mut counterproofs_and_confs = BTreeMap::new();
                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    CounterproofData {
                        txid: event.tx.compute_txid(),
                        conf_height: event.counterproof_block_height,
                        completed_signatures,
                    },
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_bridge_proof: Some((bridge_proof_tx, proof)),
                    counterproofs_and_confs,
                    counterproof_nacks: BTreeMap::new(),
                    stake_spent,
                    payout_connector_spent,
                };

                Ok(GSMOutput::with_duties(nack_duties))
            }
            GraphState::CounterProofPosted {
                mut counterproofs_and_confs,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid,
                contest_block_height,
                refuted_bridge_proof,
                counterproof_nacks,
                stake_spent,
                payout_connector_spent,
                ..
            } => {
                if counterproofs_and_confs.contains_key(&event.counterprover_idx) {
                    return Err(GSMError::duplicate(self.state.clone(), event.into()));
                }

                let (nack_duties, completed_signatures) =
                    self.validate_counterproof_and_nack(&cfg, &event, &graph_data, &graph_summary)?;

                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    CounterproofData {
                        txid: event.tx.compute_txid(),
                        conf_height: event.counterproof_block_height,
                        completed_signatures,
                    },
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.counterproof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_bridge_proof,
                    counterproofs_and_confs,
                    counterproof_nacks,
                    stake_spent,
                    payout_connector_spent,
                };

                Ok(GSMOutput::with_duties(nack_duties))
            }
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }

    /// Validates the counterproof txid, decodes the per-byte operator signatures from its
    /// witness, and builds a [`GraphDuty::PublishCounterProofNack`] duty if the current operator
    /// is the POV and the signatures decode. Returns the duties alongside the decoded signatures
    /// so the caller can persist them on [`CounterproofData`].
    fn validate_counterproof_and_nack(
        &self,
        cfg: &GraphSMCfg,
        event: &CounterProofConfirmedEvent,
        graph_data: &DepositParams,
        graph_summary: &GameGraphSummary,
    ) -> GSMResult<(Vec<GraphDuty>, Option<CompletedSignatures>)> {
        let counterproof_txid = event.tx.compute_txid();

        // Resolve the watchtower slot associated with the given counterproof transaction.
        let (watchtower_slot, _) = graph_summary
            .counterproofs
            .iter()
            .enumerate()
            .find(|(_slot, summary)| summary.counterproof == counterproof_txid)
            .ok_or_else(|| {
                GSMError::rejected(
                    self.state.clone(),
                    event.clone().into(),
                    "Invalid counterproof transaction",
                )
            })?;

        let Some(completed_signatures) = decode_completed_sigs(&event.tx) else {
            warn!(
                graph_idx = ?self.context().graph_idx(),
                counterprover_idx = event.counterprover_idx,
                %counterproof_txid,
                "counterproof witness does not decode into per-byte signatures"
            );
            return Ok((Vec::new(), None));
        };

        let pov_idx = self.context().operator_table().pov_idx();
        let duties = if self.context().operator_idx() == pov_idx {
            let setup_params = self.context().generate_setup_params(cfg, graph_data);
            let connectors =
                GameConnectors::new(graph_data.game_index, &cfg.game_graph_params, &setup_params);

            let counterproof_connector =
                connectors
                    .counterproof
                    .get(watchtower_slot)
                    .ok_or_else(|| {
                        GSMError::rejected(
                            self.state.clone(),
                            event.clone().into(),
                            format!(
                                "missing counterproof connector for watchtower slot \
                                 {watchtower_slot}"
                            ),
                        )
                    })?;

            let nack_data = CounterproofNackData { counterproof_txid };
            let counterproof_nack_tx = CounterproofNackTx::new(nack_data, *counterproof_connector);

            vec![GraphDuty::PublishCounterProofNack {
                deposit_idx: self.context().deposit_idx(),
                counterprover_idx: event.counterprover_idx,
                completed_signatures,
                counterproof_nack_tx,
            }]
        } else {
            Vec::new()
        };

        Ok((duties, Some(completed_signatures)))
    }
}

/// Decodes the per-byte operator signatures from an on-chain Counterproof tx, in byte order.
fn decode_completed_sigs(counterproof_tx: &Transaction) -> Option<CompletedSignatures> {
    // `+ 3` accounts for the trailing n-of-n signature, leaf script, and control block
    // that follow the per-byte operator signatures in the counterproof witness.
    const WANT: usize = COUNTERPROOF_N_DATA + 3;

    let witness = &counterproof_tx.input.first()?.witness;
    if witness.len() != WANT {
        return None;
    }

    // Witness layout is `[sig_{N-1}, .., sig_0, n-of-n sig, leaf script, control block]`.
    // Reversing the first N items recovers `[sig_0, .., sig_{N-1}]`.
    let mut sigs = witness
        .iter()
        .take(COUNTERPROOF_N_DATA)
        .map(|item| Signature::from_slice(item).ok())
        .collect::<Option<Vec<_>>>()?;
    sigs.reverse();

    sigs.try_into().ok()
}
