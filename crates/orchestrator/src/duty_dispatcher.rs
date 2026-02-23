//! Provides interface for dispatching duties to the appropriate executors.

use std::sync::Arc;

use strata_bridge_exec::{
    config::ExecutionConfig, deposit::execute_deposit_duty, graph::execute_graph_duty,
    output_handles::OutputHandles,
};
use tracing::error;

use crate::sm_types::UnifiedDuty;

// TODO: (@Rajil1213) Add a `duty_tracker` to keep track of which duties have been executed, which
// are pending, and which have failed, in order to implement retries and better error handling.

/// The `DutyDispatcher` is responsible for dispatching duties emitted by the state machines to the
/// appropriate executors.
#[expect(missing_debug_implementations)]
pub struct DutyDispatcher {
    cfg: Arc<ExecutionConfig>,
    handles: Arc<OutputHandles>,
}

impl DutyDispatcher {
    /// Creates a new `DutyDispatcher` with the given configuration and output handles.
    pub const fn new(cfg: Arc<ExecutionConfig>, handles: Arc<OutputHandles>) -> Self {
        Self { cfg, handles }
    }

    /// Dispatches a duty to the appropriate executor.
    ///
    /// Each such duty execution is designed to be fire-and-forget, meaning that the duty is
    /// executed in a separate task and any errors that occur during execution are logged but do not
    /// affect the main flow of the program. This allows the `DutyDispatcher` to continue
    /// dispatching other duties without being blocked by any individual duty execution, while still
    /// ensuring that any issues with duty execution are recorded for later analysis and debugging.
    /// This, however, assumes that each duty execution is **idempotent**. The burden to maintain
    /// this property falls upon the implementers of the duty executors, and it is crucial for
    /// ensuring the robustness and reliability of the overall system.
    pub async fn dispatch(&self, duty: UnifiedDuty) {
        let cfg = self.cfg.clone();
        let handles = self.handles.clone();
        match duty {
            UnifiedDuty::Deposit(deposit_duty) => {
                let _ = tokio::task::spawn(async move {
                    execute_deposit_duty(cfg.clone(), handles.clone(), &deposit_duty)
                        .await
                        .inspect_err(|err| {
                            error!(%err, ?deposit_duty, "failed to execute deposit duty");
                        })
                })
                .await
                .inspect_err(|e| {
                    error!(%e, "failed to spawn task for deposit duty");
                });
            }
            UnifiedDuty::Graph(graph_duty) => {
                let _ = tokio::task::spawn(async move {
                    execute_graph_duty(cfg, handles, &graph_duty)
                        .await
                        .inspect_err(|err| {
                            error!(%err, ?graph_duty, "failed to execute graph duty");
                        })
                })
                .await
                .inspect_err(|e| {
                    error!(%e, "failed to spawn task for graph duty");
                });
            }
        }
    }
}
