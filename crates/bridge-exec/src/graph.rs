//! This module contains the executors for performing duties emitted in the Graph State Machine
//! transitions.

use std::sync::Arc;

use strata_bridge_sm::graph::duties::GraphDuty;

use crate::{config::ExecutionConfig, output_handles::OutputHandles};

/// Executes the given graph duty.
#[allow(unused_variables)]
pub async fn execute_graph_duty(
    cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    duty: &GraphDuty,
) {
    match duty {
        GraphDuty::VerifyAdaptors(messages) => {
            todo!("VerifyAdaptors")
        }
        GraphDuty::PublishGraphNonces {
            deposit_idx,
            operator_idx,
        } => {
            todo!("PublishGraphNonces")
        }
        GraphDuty::PublishGraphPartials {
            deposit_idx,
            operator_idx,
            agg_nonce,
            claim_txid,
        } => {
            todo!("PublishGraphPartials")
        }
        GraphDuty::PublishClaim { claim_txid } => {
            todo!("PublishClaim")
        }
        GraphDuty::PublishUncontestedPayout {
            uncontested_payout_txid,
        } => {
            todo!("PublishUncontestedPayout")
        }
        GraphDuty::PublishContest { claim_txid } => {
            todo!("PublishContest")
        }
        GraphDuty::PublishBridgeProof {
            deposit_idx,
            operator_idx,
        } => {
            todo!("PublishBridgeProof")
        }
        GraphDuty::PublishBridgeProofTimeout { timeout_tx } => {
            todo!("PublishBridgeProofTimeout")
        }
        GraphDuty::PublishCounterProof {
            deposit_idx,
            operator_idx,
            proof,
        } => {
            todo!("PublishCounterProof")
        }
        GraphDuty::PublishCounterProofAck {
            counter_proof_ack_tx,
        } => {
            todo!("PublishCounterProofAck")
        }
        GraphDuty::PublishCounterProofNack {
            deposit_idx,
            counter_prover_idx,
        } => {
            todo!("PublishCounterProofNack")
        }
        GraphDuty::PublishSlash { slash_tx } => {
            todo!("PublishSlash")
        }
        GraphDuty::PublishContestedPayout {
            contested_payout_tx,
        } => {
            todo!("PublishContestedPayout")
        }
    }
}
