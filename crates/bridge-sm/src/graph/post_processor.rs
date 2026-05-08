//! Post-STF duty derivation for the Graph State Machine.

use bitcoin::hashes::{Hash, sha256};
use strata_bridge_tx_graph::{
    game_graph::{DepositParams, GameConnectors},
    transactions::prelude::{UnstakingBurnData, UnstakingBurnTx},
};
use tracing::warn;

use crate::{
    cross_sm_context::CrossSmContext,
    graph::{config::GraphSMCfg, duties::GraphDuty, machine::GraphSM, state::GraphState},
};

impl GraphSM {
    pub(crate) fn run_graph_post_stf_hook(
        &self,
        cfg: &GraphSMCfg,
        cross_sm_context: &CrossSmContext,
    ) -> Vec<GraphDuty> {
        self.derive_unstaking_burn_duty(cfg, cross_sm_context)
            .into_iter()
            .collect()
    }

    fn derive_unstaking_burn_duty(
        &self,
        cfg: &GraphSMCfg,
        cross_sm_context: &CrossSmContext,
    ) -> Option<GraphDuty> {
        let unstaking_preimage = cross_sm_context.unstaking_preimage()?;

        if self.context().operator_idx() == self.context().operator_table().pov_idx() {
            return None;
        }

        let preimage_hash = sha256::Hash::hash(&unstaking_preimage);
        if preimage_hash != self.context().unstaking_image() {
            warn!(
                graph_idx = %self.context().graph_idx(),
                expected = %self.context().unstaking_image(),
                actual = %preimage_hash,
                "cross-SM unstaking preimage does not match graph image"
            );
            return None;
        }

        let candidate = BurnCandidate::from_state(self.state())?;
        let setup_params = self
            .context()
            .generate_setup_params(cfg, candidate.graph_data);
        let connectors = GameConnectors::new(
            candidate.graph_data.game_index,
            &cfg.game_graph_params,
            &setup_params,
        );
        let unstaking_burn_tx = UnstakingBurnTx::new(
            UnstakingBurnData {
                claim_txid: candidate.claim_txid,
            },
            connectors.claim_payout,
        );

        Some(GraphDuty::PublishUnstakingBurn {
            graph_idx: self.context().graph_idx(),
            unstaking_burn_tx,
            unstaking_preimage,
        })
    }
}

struct BurnCandidate<'a> {
    graph_data: &'a DepositParams,
    claim_txid: bitcoin::Txid,
}

impl<'a> BurnCandidate<'a> {
    const fn from_state(state: &'a GraphState) -> Option<Self> {
        match state {
            GraphState::Claimed {
                graph_data,
                graph_summary,
                payout_connector_spent: None,
                ..
            }
            | GraphState::Contested {
                graph_data,
                graph_summary,
                payout_connector_spent: None,
                ..
            }
            | GraphState::BridgeProofPosted {
                graph_data,
                graph_summary,
                payout_connector_spent: None,
                ..
            }
            | GraphState::CounterProofPosted {
                graph_data,
                graph_summary,
                payout_connector_spent: None,
                ..
            } => Some(Self {
                graph_data,
                claim_txid: graph_summary.claim,
            }),

            GraphState::BridgeProofTimedout {
                graph_data,
                claim_txid,
                ..
            }
            | GraphState::Acked {
                graph_data,
                claim_txid,
                ..
            }
            | GraphState::AllNackd {
                graph_data,
                claim_txid,
                ..
            } => Some(Self {
                graph_data,
                claim_txid: *claim_txid,
            }),

            GraphState::Created { .. }
            | GraphState::GraphGenerated { .. }
            | GraphState::AdaptorsVerified { .. }
            | GraphState::NoncesCollected { .. }
            | GraphState::GraphSigned { .. }
            | GraphState::Assigned { .. }
            | GraphState::Fulfilled { .. }
            | GraphState::Claimed {
                payout_connector_spent: Some(_),
                ..
            }
            | GraphState::Contested {
                payout_connector_spent: Some(_),
                ..
            }
            | GraphState::BridgeProofPosted {
                payout_connector_spent: Some(_),
                ..
            }
            | GraphState::CounterProofPosted {
                payout_connector_spent: Some(_),
                ..
            }
            | GraphState::Withdrawn { .. }
            | GraphState::Slashed { .. }
            | GraphState::Aborted { .. } => None,
        }
    }
}
