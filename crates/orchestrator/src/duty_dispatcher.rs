//! Provides interface for dispatching duties to the appropriate executors.

use std::{any::Any, panic::AssertUnwindSafe, sync::Arc, time::Instant};

use futures::FutureExt;
use strata_bridge_exec::{
    config::ExecutionConfig, deposit::execute_deposit_duty, errors::ExecutorError,
    graph::execute_graph_duty, output_handles::OutputHandles, stake::execute_stake_duty,
};
use tracing::{Instrument, debug, error, info_span};

use crate::{observability, sm_types::UnifiedDuty};

// TODO: <https://alpenlabs.atlassian.net/browse/STR-2698>
// Add a `duty_tracker` to track executed, pending, and failed duties for retries and better error
// handling.

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
    pub fn dispatch(&self, duty: UnifiedDuty) {
        let duty_kind = observability::duty_kind(&duty);
        let duty_context = observability::duty_context(&duty);
        observability::record_duty(duty_kind, "dispatched", "none");

        let cfg = self.cfg.clone();
        let handles = self.handles.clone();
        let span = info_span!(
            "bridge_duty_execution",
            duty_kind,
            duty = %duty_context,
            result = tracing::field::Empty,
        );
        let task = async move {
            let started = Instant::now();
            observability::record_duty_started(duty_kind);
            let execution = execute_duty(cfg, handles, &duty);

            match AssertUnwindSafe(execution).catch_unwind().await {
                Ok(Ok(())) => {
                    observability::record_duty(duty_kind, "success", "none");
                    observability::record_duty_duration(duty_kind, "success", started.elapsed());
                    tracing::Span::current().record("result", "success");
                    debug!(duty_kind, "duty execution completed");
                }
                Ok(Err(execution_error)) => {
                    let error_class = observability::executor_error_class(&execution_error);
                    observability::record_duty(duty_kind, "error", error_class);
                    observability::record_duty_duration(duty_kind, "error", started.elapsed());
                    tracing::Span::current().record("result", "error");
                    error!(
                        error = %execution_error,
                        error_class,
                        duty_kind,
                        "duty execution failed"
                    );
                }
                Err(panic_payload) => {
                    observability::record_duty(duty_kind, "panic", "panic");
                    observability::record_duty_duration(duty_kind, "panic", started.elapsed());
                    tracing::Span::current().record("result", "panic");
                    error!(
                        panic = panic_payload_message(panic_payload.as_ref()),
                        duty_kind, "duty execution panicked"
                    );
                }
            }

            observability::record_duty_settled(duty_kind);
        }
        .instrument(span);

        // Duty tasks are intentionally detached, but all executor errors and task panics are
        // handled inside the task before the join handle is dropped.
        drop(tokio::task::spawn(task));
    }
}

async fn execute_duty(
    cfg: Arc<ExecutionConfig>,
    handles: Arc<OutputHandles>,
    duty: &UnifiedDuty,
) -> Result<(), ExecutorError> {
    match duty {
        UnifiedDuty::Deposit(deposit_duty) => {
            execute_deposit_duty(cfg, handles, deposit_duty).await
        }
        UnifiedDuty::Graph(graph_duty) => execute_graph_duty(cfg, handles, graph_duty).await,
        UnifiedDuty::Stake(stake_duty) => execute_stake_duty(cfg, handles, stake_duty).await,
    }
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "non-string panic payload"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_payload_message_preserves_string_context() {
        let owned = "owned panic".to_owned();
        let borrowed = "borrowed panic";

        assert_eq!(panic_payload_message(&owned), "owned panic");
        assert_eq!(panic_payload_message(&borrowed), "borrowed panic");
        assert_eq!(panic_payload_message(&42_u64), "non-string panic payload");
    }
}
