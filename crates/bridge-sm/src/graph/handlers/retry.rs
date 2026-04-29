use std::sync::Arc;

use musig2::secp256k1::schnorr::Signature;
use strata_bridge_primitives::{proof::verify_bridge_proof, types::OperatorIdx};
use strata_bridge_tx_graph::{
    game_graph::{DepositParams, GameConnectors},
    musig_functor::GameFunctor,
    transactions::prelude::{CounterproofNackData, CounterproofNackTx},
};
use zkaleido::ProofReceipt;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::RetryTickEvent,
    machine::{GSMOutput, GraphSM, generate_game_graph},
    state::GraphState,
    watchtower::watchtower_slot_for_operator,
};

impl GraphSM {
    /// Emits retriable duties for the current state.
    pub(crate) fn process_retry_tick(&self, cfg: Arc<GraphSMCfg>) -> GSMResult<GSMOutput> {
        let duties = match self.state() {
            GraphState::GraphGenerated { graph_data, .. }
                if self.context().operator_idx() != self.context().operator_table().pov_idx() =>
            {
                let game_graph = generate_game_graph(&cfg, self.context(), graph_data);
                let pov_operator_idx = self.context().operator_table().pov_idx();
                let counterproof_idx = watchtower_slot_for_operator(
                    self.context().operator_idx(),
                    self.context().operator_table().pov_idx(),
                )
                .expect("graph owner has no watchtower index");

                let pov_counterproof_graph = game_graph
                    .counterproofs
                    .get(counterproof_idx)
                    .ok_or_else(|| {
                        GSMError::rejected(
                            self.state().clone(),
                            RetryTickEvent.into(),
                            format!("Missing counterproof for watchtower {pov_operator_idx}"),
                        )
                    })?;
                let adaptor_pubkey = *graph_data
                    .adaptor_pubkeys
                    .get(counterproof_idx)
                    .ok_or_else(|| {
                        GSMError::rejected(
                            self.state().clone(),
                            RetryTickEvent.into(),
                            format!("Missing adaptor pubkey for watchtower {pov_operator_idx}"),
                        )
                    })?;
                let fault_pubkey =
                    *graph_data
                        .fault_pubkeys
                        .get(counterproof_idx)
                        .ok_or_else(|| {
                            GSMError::rejected(
                                self.state().clone(),
                                RetryTickEvent.into(),
                                format!("Missing fault pubkey for watchtower {pov_operator_idx}"),
                            )
                        })?;

                vec![GraphDuty::VerifyAdaptors {
                    graph_idx: self.context().graph_idx(),
                    watchtower_idx: pov_operator_idx,
                    sighashes: pov_counterproof_graph.counterproof.sighashes(),
                    adaptor_pubkey,
                    fault_pubkey,
                }]
            }
            GraphState::Fulfilled {
                graph_data,
                coop_payout_failed,
                assignee,
                ..
            } if *coop_payout_failed
                && self.context().operator_idx() == self.context().operator_table().pov_idx()
                && self.context().operator_idx() == *assignee =>
            {
                let game_graph = generate_game_graph(&cfg, self.context(), graph_data);

                vec![GraphDuty::PublishClaim {
                    claim_tx: game_graph.claim,
                }]
            }
            GraphState::Claimed {
                fulfillment_txid, ..
            } if fulfillment_txid.is_none() => {
                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2192>
                // Implement the faulty cases in `process_claim`; this emits `PublishContest`.
                Vec::new()
            }
            GraphState::Contested {
                graph_data,
                graph_summary,
                ..
            } if self.context().operator_idx() == self.context().operator_table().pov_idx() => {
                let setup_params = self.context().generate_setup_params(&cfg, graph_data);
                let connectors = GameConnectors::new(
                    graph_data.game_index,
                    &cfg.game_graph_params,
                    &setup_params,
                );

                vec![GraphDuty::GenerateAndPublishBridgeProof {
                    graph_idx: self.context().graph_idx(),
                    contest_txid: graph_summary.contest,
                    game_index: graph_data.game_index,
                    contest_proof_connector: connectors.contest_proof,
                }]
            }
            GraphState::BridgeProofPosted {
                graph_data,
                signatures,
                proof,
                ..
            } if self.context().operator_idx() != self.context().operator_table().pov_idx()
                && !verify_bridge_proof(&cfg.bridge_proof_predicate, proof) =>
            {
                vec![self.generate_counterproof_duty(&cfg, graph_data, signatures, proof)?]
            }
            GraphState::CounterProofPosted {
                graph_data,
                graph_summary,
                signatures,
                refuted_proof,
                counterproofs_and_confs,
                counterproof_nacks,
                ..
            } => {
                let pov_idx = self.context().operator_table().pov_idx();
                let is_pov_graph = self.context().operator_idx() == pov_idx;

                if is_pov_graph {
                    let setup_params = self.context().generate_setup_params(&cfg, graph_data);
                    let connectors = GameConnectors::new(
                        graph_data.game_index,
                        &cfg.game_graph_params,
                        &setup_params,
                    );

                    let mut duties: Vec<GraphDuty> = Vec::new();

                    if refuted_proof.is_none() {
                        duties.push(GraphDuty::GenerateAndPublishBridgeProof {
                            graph_idx: self.context().graph_idx(),
                            contest_txid: graph_summary.contest,
                            game_index: graph_data.game_index,
                            contest_proof_connector: connectors.contest_proof,
                        });
                    }

                    // Retry NACKs for confirmed counterproofs that have not been NACK'd yet.
                    duties.extend(
                        counterproofs_and_confs
                            .iter()
                            .filter(|(idx, _)| !counterproof_nacks.contains_key(idx))
                            .filter_map(|(counterprover_idx, data)| {
                                let watchtower_slot =
                                    watchtower_slot_for_operator(pov_idx, *counterprover_idx)?;
                                let counterproof_connector =
                                    connectors.counterproof.get(watchtower_slot)?;

                                let nack_data = CounterproofNackData {
                                    counterproof_txid: data.txid,
                                };
                                let counterproof_nack_tx =
                                    CounterproofNackTx::new(nack_data, *counterproof_connector);

                                Some(GraphDuty::PublishCounterProofNack {
                                    deposit_idx: self.context().deposit_idx(),
                                    counterprover_idx: *counterprover_idx,
                                    completed_signatures: data.completed_signatures,
                                    counterproof_nack_tx,
                                })
                            }),
                    );

                    duties
                } else {
                    // PoV operator is NOT the graph owner: retry counterproof when an
                    // invalid bridge proof exists and PoV operator's counterproof has not
                    // appeared on chain yet.
                    if let Some(proof) = refuted_proof
                        && !verify_bridge_proof(&cfg.bridge_proof_predicate, proof)
                        && !counterproofs_and_confs.contains_key(&pov_idx)
                    {
                        vec![self.generate_counterproof_duty(&cfg, graph_data, signatures, proof)?]
                    } else {
                        Vec::new()
                    }
                }
            }
            _ => Vec::new(),
        };

        Ok(GSMOutput::with_duties(duties))
    }

    fn generate_counterproof_duty(
        &self,
        cfg: &GraphSMCfg,
        graph_data: &DepositParams,
        signatures: &[Signature],
        proof: &ProofReceipt,
    ) -> GSMResult<GraphDuty> {
        let game_graph = generate_game_graph(cfg, self.context(), graph_data);
        let watchtower_idx = watchtower_slot_for_operator(
            self.context().operator_idx(),
            self.context().operator_table().pov_idx(),
        )
        .expect("watchtower slot must exist for non-pov operator");

        let counterproof_graph = game_graph
            .counterproofs
            .get(watchtower_idx)
            .ok_or_else(|| {
                GSMError::rejected(
                    self.state().clone(),
                    RetryTickEvent.into(),
                    format!("missing counterproof graph for watchtower {watchtower_idx}"),
                )
            })?;

        let n_of_n_signature = GameFunctor::unpack(
            signatures.to_vec(),
            self.context().watchtower_pubkeys().len(),
        )
        .expect("failed to unpack graph signatures for counterproof N/N signature")
        .watchtowers[watchtower_idx]
            .counterproof[0];

        Ok(GraphDuty::GenerateAndPublishCounterProof {
            graph_idx: self.context().graph_idx(),
            counterproof_tx: counterproof_graph.counterproof.clone(),
            watchtower_idx: watchtower_idx as OperatorIdx,
            n_of_n_signature,
            proof: proof.clone(),
        })
    }
}
