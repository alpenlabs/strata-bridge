use std::{collections::BTreeMap, sync::Arc};

use strata_bridge_tx_graph::{
    game_graph::{DepositParams, GameConnectors, GameGraphSummary},
    transactions::prelude::{CounterproofNackData, CounterproofNackTx},
};

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::CounterProofConfirmedEvent,
    machine::{GSMOutput, GraphSM},
    state::GraphState,
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
                ..
            } => {
                let nack_duties =
                    self.validate_counterproof_and_nack(&cfg, &event, &graph_data, &graph_summary)?;

                let mut counterproofs_and_confs = BTreeMap::new();
                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    (event.counterproof_txid, event.counterproof_block_height),
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.counterproof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_proof: None,
                    counterproofs_and_confs,
                    counterproof_nacks: BTreeMap::new(),
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
                ..
            } => {
                let nack_duties =
                    self.validate_counterproof_and_nack(&cfg, &event, &graph_data, &graph_summary)?;

                let mut counterproofs_and_confs = BTreeMap::new();
                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    (event.counterproof_txid, event.counterproof_block_height),
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_proof: Some(proof),
                    counterproofs_and_confs,
                    counterproof_nacks: BTreeMap::new(),
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
                refuted_proof,
                counterproof_nacks,
                ..
            } => {
                if counterproofs_and_confs.contains_key(&event.counterprover_idx) {
                    return Err(GSMError::duplicate(self.state.clone(), event.into()));
                }

                let nack_duties =
                    self.validate_counterproof_and_nack(&cfg, &event, &graph_data, &graph_summary)?;

                counterproofs_and_confs.insert(
                    event.counterprover_idx,
                    (event.counterproof_txid, event.counterproof_block_height),
                );

                self.state = GraphState::CounterProofPosted {
                    last_block_height: event.counterproof_block_height,
                    graph_data,
                    graph_summary,
                    signatures,
                    fulfillment_txid,
                    contest_block_height,
                    refuted_proof,
                    counterproofs_and_confs,
                    counterproof_nacks,
                };

                Ok(GSMOutput::with_duties(nack_duties))
            }
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }

    /// Validates the counterproof txid and builds a [`GraphDuty::PublishCounterProofNack`] duty
    /// if the current operator is the POV.
    fn validate_counterproof_and_nack(
        &self,
        cfg: &GraphSMCfg,
        event: &CounterProofConfirmedEvent,
        graph_data: &DepositParams,
        graph_summary: &GameGraphSummary,
    ) -> GSMResult<Vec<GraphDuty>> {
        // Resolve the watchtower slot associated with the given counterproof transaction.
        let (watchtower_slot, _) = graph_summary
            .counterproofs
            .iter()
            .enumerate()
            .find(|(_slot, summary)| summary.counterproof == event.counterproof_txid)
            .ok_or_else(|| {
                GSMError::rejected(
                    self.state.clone(),
                    event.clone().into(),
                    "Invalid counterproof transaction",
                )
            })?;

        let pov_idx = self.context().operator_table().pov_idx();
        let duties = if self.context().operator_idx() == pov_idx {
            let setup_params = self.context().generate_setup_params(cfg);
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

            let nack_data = CounterproofNackData {
                counterproof_txid: event.counterproof_txid,
            };
            let counterproof_nack_tx = CounterproofNackTx::new(nack_data, *counterproof_connector);

            vec![GraphDuty::PublishCounterProofNack {
                deposit_idx: self.context().deposit_idx(),
                counter_prover_idx: event.counterprover_idx,
                counterproof_nack_tx: counterproof_nack_tx.as_ref().clone(),
            }]
        } else {
            Vec::new()
        };

        Ok(duties)
    }
}
