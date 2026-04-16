//! The fixed-point batch processor for state machine events.
//!
//! The [`Applicator`] owns the STF execution, signal cascade, duty accumulation, and persistence
//! tracking logic. It provides a single entry point ([`apply_batch`](Applicator::apply_batch)) that
//! processes a set of seed events to a fixed point — all signals are drained and no intermediate
//! state is externally visible until the batch settles.
//!
//! Both on-chain (per-transaction) and off-chain (per-event) paths use the same `Applicator`,
//! ensuring uniform batch semantics across the pipeline.

use std::collections::VecDeque;

use strata_bridge_sm::graph::{
    duties::GraphDuty,
    events::{AdaptorsVerifiedEvent, GraphEvent},
};
use tracing::{info, warn};

use crate::{
    errors::PipelineError,
    persister::PersistenceTracker,
    signals_router,
    sm_registry::{IgnoredEventReason, ProcessOutcome, SMRegistry},
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// A fixed-point batch processor that drives state machine transitions and signal cascades.
///
/// Created once per top-level event (off-chain) or once per block (on-chain), the `Applicator`
/// accumulates duties and tracks persistence across one or more [`apply_batch`](Self::apply_batch)
/// calls, then yields its results via [`finish`](Self::finish).
#[expect(missing_debug_implementations)]
pub struct Applicator<'a> {
    registry: &'a mut SMRegistry,
    tracker: PersistenceTracker,
    duties: Vec<UnifiedDuty>,
    signal_queue: VecDeque<(SMId, SMEvent)>,
}

impl<'a> Applicator<'a> {
    /// Creates a new `Applicator` bound to the given registry.
    pub fn new(registry: &'a mut SMRegistry) -> Self {
        Self {
            registry,
            tracker: PersistenceTracker::new(),
            duties: Vec::new(),
            signal_queue: VecDeque::new(),
        }
    }

    /// Returns a shared reference to the underlying registry.
    ///
    /// This is safe to call between `apply_batch` calls to inspect settled state (e.g., to derive
    /// the active operator snapshot before classifying the next transaction in a block).
    pub const fn registry(&self) -> &SMRegistry {
        self.registry
    }

    /// Returns a mutable reference to the underlying registry.
    ///
    /// Needed by callers that must mutate the registry between batches (e.g., registering new SMs
    /// discovered during block classification).
    pub const fn registry_mut(&mut self) -> &mut SMRegistry {
        self.registry
    }

    /// Processes a batch of seed events to a fixed point.
    ///
    /// This method:
    /// 1. Processes each seed event through the state transition function.
    /// 2. Fabricates any follow-up events (e.g., `AdaptorsVerified` after `VerifyAdaptors`).
    /// 3. Drains the signal queue until no more signals remain.
    /// 4. Accumulates all duties produced.
    /// 5. Updates the persistence tracker for every touched state machine.
    ///
    /// No intermediate state is externally visible until this method returns.
    pub fn apply_batch(
        &mut self,
        seed_events: impl IntoIterator<Item = (SMId, SMEvent)>,
    ) -> Result<(), PipelineError> {
        // Process initial seed events
        for (sm_id, sm_event) in seed_events {
            self.apply_one(sm_id, sm_event)?;
        }

        // Fabricate follow-up events for any VerifyAdaptors duties produced by this batch
        let fabricated: Vec<_> = self
            .duties
            .iter()
            .filter_map(|duty| {
                if let UnifiedDuty::Graph(GraphDuty::VerifyAdaptors { graph_idx, .. }) = duty {
                    Some((
                        (*graph_idx).into(),
                        SMEvent::from(GraphEvent::AdaptorsVerified(AdaptorsVerifiedEvent {})),
                    ))
                } else {
                    None
                }
            })
            .collect();

        for (sm_id, event) in fabricated {
            info!(?sm_id, "enqueuing fabricated AdaptorsVerified event");
            self.signal_queue.push_back((sm_id, event));
        }

        // Drain signal cascade to fixed point
        while let Some((sm_id, sm_event)) = self.signal_queue.pop_front() {
            self.apply_one(sm_id, sm_event)?;
        }

        Ok(())
    }

    /// Adds duties directly (e.g., initial duties from newly created SMs that are not produced by
    /// the STF but by SM constructors).
    pub fn add_duties(&mut self, duties: impl IntoIterator<Item = UnifiedDuty>) {
        self.duties.extend(duties);
    }

    /// Consumes the applicator and returns the accumulated duties and persistence tracker.
    pub fn finish(self) -> (Vec<UnifiedDuty>, PersistenceTracker) {
        (self.duties, self.tracker)
    }

    /// Processes a single event through the registry's STF.
    ///
    /// On success, accumulates duties and enqueues any signal-derived events. Ignored outcomes
    /// (duplicates, rejections) are non-fatal and logged. Fatal errors are propagated.
    fn apply_one(&mut self, sm_id: SMId, sm_event: SMEvent) -> Result<(), PipelineError> {
        match self.registry.process_event(&sm_id, sm_event) {
            Ok(ProcessOutcome::Applied(output)) => {
                self.duties.extend(output.duties);
                self.tracker.record(sm_id);

                for signal in output.signals {
                    for (target_id, target_event) in
                        signals_router::route_signal(self.registry, signal)
                    {
                        self.tracker.link(sm_id, target_id);
                        self.signal_queue.push_back((target_id, target_event));
                    }
                }

                Ok(())
            }
            Ok(ProcessOutcome::Ignored { id, event, reason }) => {
                match reason {
                    IgnoredEventReason::Duplicate => {
                        warn!(?id, %event, "duplicate event, skipping");
                    }
                    IgnoredEventReason::Rejected(rejected_reason) => {
                        warn!(?id, %event, %rejected_reason, "event rejected by state machine, skipping");
                    }
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}
