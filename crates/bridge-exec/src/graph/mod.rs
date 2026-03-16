//! This module contains the executors for performing duties emitted in the Graph State Machine
//! transitions.

mod common;
mod contested;
mod uncontested;
mod utils;

use std::sync::Arc;

use strata_bridge_p2p_types::{NagRequest, NagRequestPayload};
use strata_bridge_sm::graph::duties::GraphDuty;
use tracing::info;

use crate::{
    config::ExecutionConfig,
    errors::ExecutorError,
    graph::{
        common::{publish_claim, publish_graph_nonces, publish_graph_partials, verify_adaptors},
        contested::{publish_bridge_proof_timeout, publish_contested_payout},
        uncontested::publish_uncontested_payout,
    },
    output_handles::OutputHandles,
};

/// Executes the given graph duty.
pub async fn execute_graph_duty(
    cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    duty: &GraphDuty,
) -> Result<(), ExecutorError> {
    match duty {
        GraphDuty::GenerateGraphData { graph_idx } => {
            common::generate_graph_data(&cfg, &output_handles, *graph_idx).await
        }
        GraphDuty::VerifyAdaptors {
            graph_idx,
            watchtower_idx,
            sighashes,
        } => verify_adaptors(*graph_idx, *watchtower_idx, sighashes).await,
        GraphDuty::PublishGraphNonces {
            graph_idx,
            graph_inpoints,
            graph_tweaks,
            ordered_pubkeys,
        } => {
            publish_graph_nonces(
                &output_handles,
                *graph_idx,
                graph_inpoints,
                graph_tweaks,
                ordered_pubkeys,
            )
            .await
        }
        GraphDuty::PublishGraphPartials {
            graph_idx,
            agg_nonces,
            sighashes,
            graph_inpoints,
            graph_tweaks,
            claim_txid,
            ordered_pubkeys,
        } => {
            publish_graph_partials(
                &output_handles,
                *graph_idx,
                agg_nonces,
                sighashes,
                graph_inpoints,
                graph_tweaks,
                *claim_txid,
                ordered_pubkeys,
            )
            .await
        }
        GraphDuty::PublishClaim { claim_tx } => publish_claim(&output_handles, claim_tx).await,
        GraphDuty::PublishUncontestedPayout {
            signed_uncontested_payout_tx,
        } => publish_uncontested_payout(&output_handles, signed_uncontested_payout_tx).await,
        GraphDuty::PublishContest { .. } => {
            todo!("PublishContest")
        }
        GraphDuty::PublishBridgeProof { .. } => {
            todo!("PublishBridgeProof")
        }
        GraphDuty::PublishBridgeProofTimeout { signed_timeout_tx } => {
            publish_bridge_proof_timeout(&output_handles, signed_timeout_tx).await
        }
        GraphDuty::PublishCounterProof { .. } => {
            todo!("PublishCounterProof")
        }
        GraphDuty::PublishCounterProofAck { .. } => {
            todo!("PublishCounterProofAck")
        }
        GraphDuty::PublishCounterProofNack { .. } => {
            todo!("PublishCounterProofNack")
        }
        GraphDuty::PublishSlash { .. } => {
            todo!("PublishSlash")
        }
        GraphDuty::PublishContestedPayout {
            signed_contested_payout_tx,
        } => publish_contested_payout(&output_handles, signed_contested_payout_tx).await,
        GraphDuty::Nag { duty } => {
            let (graph_idx, operator_idx, nag_request) = match duty {
                strata_bridge_sm::graph::duties::NagDuty::NagGraphData {
                    graph_idx,
                    operator_idx,
                    operator_pubkey,
                } => (
                    *graph_idx,
                    *operator_idx,
                    NagRequest {
                        recipient: operator_pubkey.clone(),
                        payload: NagRequestPayload::GraphData {
                            graph_idx: *graph_idx,
                        },
                    },
                ),
                strata_bridge_sm::graph::duties::NagDuty::NagGraphNonces {
                    graph_idx,
                    operator_idx,
                    operator_pubkey,
                } => (
                    *graph_idx,
                    *operator_idx,
                    NagRequest {
                        recipient: operator_pubkey.clone(),
                        payload: NagRequestPayload::GraphNonces {
                            graph_idx: *graph_idx,
                        },
                    },
                ),
                strata_bridge_sm::graph::duties::NagDuty::NagGraphPartials {
                    graph_idx,
                    operator_idx,
                    operator_pubkey,
                } => (
                    *graph_idx,
                    *operator_idx,
                    NagRequest {
                        recipient: operator_pubkey.clone(),
                        payload: NagRequestPayload::GraphPartials {
                            graph_idx: *graph_idx,
                        },
                    },
                ),
            };

            info!(%graph_idx, %operator_idx, payload = ?nag_request.payload, "executing nag duty to request missing graph peer data");

            output_handles
                .msg_handler
                .write()
                .await
                .send_nag_request(nag_request, None)
                .await;

            info!(%graph_idx, %operator_idx, "published graph nag request");
            Ok(())
        }
    }
}
