//! This module contains the executors for performing duties emitted in the Graph State Machine
//! transitions.

use std::sync::Arc;

use strata_bridge_sm::graph::duties::GraphDuty;

use crate::{config::ExecutionConfig, output_handles::OutputHandles};

/// Executes the given graph duty.
pub async fn execute_graph_duty(
    _cfg: Arc<ExecutionConfig>,
    _output_handles: Arc<OutputHandles>,
    duty: &GraphDuty,
) {
    todo!("Implement duty execution logic for: {duty:#?}");
}
