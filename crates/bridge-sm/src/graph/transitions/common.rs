use std::sync::Arc;

use bitcoin::relative::LockTime;
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_bridge_tx_graph2::musig_functor::GameFunctor;

use crate::graph::{
    config::GraphSMCfg,
    duties::GraphDuty,
    errors::{GSMError, GSMResult},
    events::NewBlockEvent,
    machine::{GSMOutput, GraphSM, generate_game_graph},
    state::GraphState,
};

impl GraphSM {
    /// Processes information about new blocks and applies any updates related to block height
    /// timeouts
    pub(crate) fn notify_new_block(
        &mut self,
        cfg: Arc<GraphSMCfg>,
        new_block_event: NewBlockEvent,
    ) -> GSMResult<GSMOutput> {
        let last_processed_block_height = self.state().last_processed_block_height();
        if last_processed_block_height.is_some_and(|height| *height >= new_block_event.block_height)
        {
            return Err(GSMError::rejected(
                self.state().clone(),
                new_block_event.into(),
                "Rejecting already processed block".to_string(),
            ));
        }

        let graph_ctx = self.context().clone();

        match self.state_mut() {
            GraphState::Created {
                last_block_height, ..
            }
            | GraphState::GraphGenerated {
                last_block_height, ..
            }
            | GraphState::AdaptorsVerified {
                last_block_height, ..
            }
            | GraphState::NoncesCollected {
                last_block_height, ..
            }
            | GraphState::GraphSigned {
                last_block_height, ..
            }
            | GraphState::Assigned {
                last_block_height, ..
            }
            | GraphState::Fulfilled {
                last_block_height, ..
            }
            | GraphState::Contested {
                last_block_height, ..
            }
            | GraphState::BridgeProofTimedout {
                last_block_height, ..
            } => {
                *last_block_height = new_block_event.block_height;
                Ok(GSMOutput::new())
            }

            GraphState::Claimed {
                last_block_height,
                graph_data,
                claim_block_height,
                signatures,
                ..
            } => {
                // Extract context values before the match to avoid borrow conflicts
                let graph_data = *graph_data;
                let claim_height = *claim_block_height;
                *last_block_height = new_block_event.block_height;

                let contest_timeout = match cfg.game_graph_params.contest_timelock {
                    LockTime::Blocks(h) => h.value() as BitcoinBlockHeight,
                    LockTime::Time(_) => {
                        return Err(GSMError::rejected(
                            self.state().clone(),
                            new_block_event.into(),
                            "Contest timelock must be height-based".to_string(),
                        ));
                    }
                };

                if new_block_event.block_height > claim_height + contest_timeout {
                    let game_graph = generate_game_graph(&cfg, &graph_ctx, graph_data);
                    let uncontested_signatures =
                        GameFunctor::unpack(signatures.clone(), cfg.watchtower_pubkeys.len())
                            .expect("Failed to retrieve uncontested payout signatures")
                            .uncontested_payout;

                    let signed_uncontested_payout_tx = game_graph
                        .uncontested_payout
                        .finalize(uncontested_signatures);

                    Ok(GSMOutput::with_duties(vec![
                        GraphDuty::PublishUncontestedPayout {
                            signed_uncontested_payout_tx,
                        },
                    ]))
                } else {
                    Ok(GSMOutput::new())
                }
            }

            // TODO: STR-2340
            GraphState::BridgeProofPosted { .. } => todo!(""),

            // TODO: STR-2196
            GraphState::CounterProofPosted { .. } => todo!(""),

            // TODO: STR-2342
            GraphState::AllNackd { .. } => todo!(""),

            // TODO: STR-2196
            GraphState::Acked { .. } => todo!(""),

            // Terminal states do not process new blocks
            GraphState::Withdrawn { .. }
            | GraphState::Slashed { .. }
            | GraphState::Aborted { .. } => Err(GSMError::rejected(
                self.state().clone(),
                new_block_event.into(),
                "New blocks irrelevant in terminal state",
            )),
        }
    }
}
