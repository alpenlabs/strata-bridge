//! This module contains the executors for performing duties emitted in the Graph State Machine
//! transitions.

mod common;
mod contested;

use std::sync::Arc;

use strata_bridge_sm::graph::duties::GraphDuty;

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

/// Executes the given graph duty.
#[expect(unused_variables)]
pub async fn execute_graph_duty(
    cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    duty: &GraphDuty,
) -> Result<(), ExecutorError> {
    match duty {
        GraphDuty::VerifyAdaptors {
            graph_idx,
            watchtower_idx,
            sighashes,
        } => common::verify_adaptors(*graph_idx, *watchtower_idx, sighashes).await,
        GraphDuty::PublishGraphNonces {
            graph_idx,
            graph_inpoints,
            graph_tweaks,
            ordered_pubkeys,
        } => {
            common::publish_graph_nonces(
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
            common::publish_graph_partials(
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
        GraphDuty::PublishClaim { claim_tx } => {
            common::publish_claim(&output_handles, claim_tx).await
        }
        GraphDuty::PublishUncontestedPayout {
            signed_uncontested_payout_tx,
        } => {
            common::publish_uncontested_payout(&output_handles, signed_uncontested_payout_tx).await
        }
        GraphDuty::PublishContest { .. } => {
            todo!("PublishContest")
        }
        GraphDuty::PublishBridgeProof { .. } => {
            todo!("PublishBridgeProof")
        }
        GraphDuty::PublishBridgeProofTimeout { signed_timeout_tx } => {
            contested::publish_bridge_proof_timeout(&output_handles, signed_timeout_tx.clone())
                .await
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
        GraphDuty::PublishContestedPayout { .. } => {
            todo!("PublishContestedPayout")
        }
    }
}
