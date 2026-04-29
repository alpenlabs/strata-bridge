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
        contested::{
            generate_and_publish_bridge_proof, generate_and_publish_counterproof,
            publish_bridge_proof_timeout, publish_contest, publish_contested_payout,
            publish_counterproof_ack, publish_slash,
        },
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
        GraphDuty::GenerateGraphData {
            graph_idx,
            deposit_outpoint,
            stake_outpoint,
            unstaking_image,
        } => {
            common::generate_graph_data(
                &cfg,
                &output_handles,
                *graph_idx,
                *deposit_outpoint,
                *stake_outpoint,
                *unstaking_image,
            )
            .await
        }
        GraphDuty::VerifyAdaptors {
            graph_idx,
            watchtower_idx,
            sighashes,
            adaptor_pubkey,
            fault_pubkey,
        } => {
            verify_adaptors(
                &output_handles,
                *graph_idx,
                *watchtower_idx,
                sighashes,
                *adaptor_pubkey,
                *fault_pubkey,
            )
            .await
        }
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
        GraphDuty::PublishContest {
            contest_tx,
            n_of_n_signature,
            watchtower_index,
        } => {
            publish_contest(
                &output_handles,
                contest_tx.clone(),
                n_of_n_signature,
                *watchtower_index,
            )
            .await
        }
        GraphDuty::GenerateAndPublishBridgeProof {
            graph_idx,
            operator_index,
            last_block_height,
            contest_txid,
            game_index,
            contest_proof_connector,
        } => {
            generate_and_publish_bridge_proof(
                &output_handles,
                graph_idx.deposit,
                *operator_index,
                *last_block_height,
                *contest_txid,
                *game_index,
                *contest_proof_connector,
            )
            .await
        }
        GraphDuty::PublishBridgeProofTimeout { signed_timeout_tx } => {
            publish_bridge_proof_timeout(&output_handles, signed_timeout_tx).await
        }
        GraphDuty::GenerateAndPublishCounterProof {
            graph_idx,
            counterproof_tx,
            watchtower_idx,
            n_of_n_signature,
            ..
        } => {
            generate_and_publish_counterproof(
                &output_handles,
                counterproof_tx.clone(),
                graph_idx.operator,
                graph_idx.deposit,
                *watchtower_idx,
                *n_of_n_signature,
            )
            .await
        }
        GraphDuty::PublishCounterProofAck {
            signed_counter_proof_ack_tx,
        } => publish_counterproof_ack(&output_handles, signed_counter_proof_ack_tx).await,
        GraphDuty::PublishCounterProofNack { .. } => {
            todo!("PublishCounterProofNack")
        }
        GraphDuty::PublishSlash { signed_slash_tx } => {
            publish_slash(&output_handles, signed_slash_tx).await
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
