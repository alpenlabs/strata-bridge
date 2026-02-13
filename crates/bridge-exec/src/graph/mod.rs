//! This module contains the executors for performing duties emitted in the Graph State Machine
//! transitions.

use std::sync::Arc;

use strata_bridge_sm::graph::duties::GraphDuty;

use crate::{config::ExecutionConfig, output_handles::OutputHandles};

/// Executes the given graph duty.
#[expect(unused_variables)]
pub async fn execute_graph_duty(
    cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    duty: &GraphDuty,
) {
    match duty {
        GraphDuty::VerifyAdaptors { .. } => {
            todo!("VerifyAdaptors")
        }
        GraphDuty::PublishGraphNonces { .. } => {
            todo!("PublishGraphNonces")
        }
        GraphDuty::PublishGraphPartials { .. } => {
            todo!("PublishGraphPartials")
        }
        GraphDuty::PublishClaim { .. } => {
            todo!("PublishClaim")
        }
        GraphDuty::PublishUncontestedPayout { .. } => {
            todo!("PublishUncontestedPayout")
        }
        GraphDuty::PublishContest { .. } => {
            todo!("PublishContest")
        }
        GraphDuty::PublishBridgeProof { .. } => {
            todo!("PublishBridgeProof")
        }
        GraphDuty::PublishBridgeProofTimeout { .. } => {
            todo!("PublishBridgeProofTimeout")
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
