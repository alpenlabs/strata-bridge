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
        // Snapshot the duty count before this batch so we only fabricate follow-up events for
        // duties produced by *this* batch, not duties accumulated from earlier batches.
        let duties_before = self.duties.len();

        // Process initial seed events
        for (sm_id, sm_event) in seed_events {
            self.apply_one(sm_id, sm_event)?;
        }

        // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2669>
        // Remove this fabrication once adaptor verification is handled properly by the GSM.
        // Fabricate follow-up events only for VerifyAdaptors duties produced by this batch.
        let fabricated: Vec<_> = self.duties[duties_before..]
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use strata_bridge_primitives::types::GraphIdx;
    use strata_bridge_sm::{
        deposit::events::{DepositEvent, NewBlockEvent as DepositNewBlock},
        graph::events::{GraphEvent, NewBlockEvent as GraphNewBlock},
    };

    use super::*;
    use crate::testing::{
        INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, test_empty_registry, test_populated_registry,
    };

    // ===== apply_batch basic tests =====

    #[test]
    fn empty_batch_yields_no_duties_and_no_touched_sms() {
        let mut registry = test_populated_registry(1);
        let mut applicator = Applicator::new(&mut registry);

        applicator.apply_batch(vec![]).unwrap();

        let (duties, tracker) = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
    }

    #[test]
    fn applied_event_marks_sm_as_touched() {
        let mut registry = test_populated_registry(1);
        let height = INITIAL_BLOCK_HEIGHT + 1;

        let mut applicator = Applicator::new(&mut registry);

        let seed_events = vec![(
            SMId::Deposit(0),
            SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
                block_height: height,
            }))),
        )];

        applicator.apply_batch(seed_events).unwrap();

        let (_, tracker) = applicator.finish();
        let batches = tracker.into_batches();
        assert!(!batches.is_empty(), "applied event must mark SM as touched");
    }

    #[test]
    fn applied_graph_event_marks_sm_as_touched() {
        let mut registry = test_populated_registry(1);
        let height = INITIAL_BLOCK_HEIGHT + 1;

        let graph_idx = GraphIdx {
            deposit: 0,
            operator: 0,
        };

        let mut applicator = Applicator::new(&mut registry);

        let seed_events = vec![(
            SMId::Graph(graph_idx),
            SMEvent::Graph(Box::new(GraphEvent::NewBlock(GraphNewBlock {
                block_height: height,
            }))),
        )];

        applicator.apply_batch(seed_events).unwrap();

        let (_, tracker) = applicator.finish();
        let batches = tracker.into_batches();
        assert!(!batches.is_empty());
    }

    #[test]
    fn successive_batches_accumulate_touched_sms() {
        let mut registry = test_populated_registry(2);
        let height = INITIAL_BLOCK_HEIGHT + 1;

        let mut applicator = Applicator::new(&mut registry);

        applicator
            .apply_batch(vec![(
                SMId::Deposit(0),
                SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
                    block_height: height,
                }))),
            )])
            .unwrap();

        applicator
            .apply_batch(vec![(
                SMId::Deposit(1),
                SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
                    block_height: height,
                }))),
            )])
            .unwrap();

        let (_, tracker) = applicator.finish();
        let all_ids: BTreeSet<_> = tracker.into_batches().into_iter().flatten().collect();
        assert!(all_ids.contains(&SMId::Deposit(0)));
        assert!(all_ids.contains(&SMId::Deposit(1)));
    }

    // ===== Error handling tests =====

    #[test]
    fn unknown_sm_id_is_fatal() {
        let mut registry = test_empty_registry();
        let mut applicator = Applicator::new(&mut registry);

        let seed_events = vec![(
            SMId::Deposit(99),
            SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
                block_height: 200,
            }))),
        )];

        let result = applicator.apply_batch(seed_events);
        assert!(result.is_err());
    }

    #[test]
    fn duplicate_event_is_ignored_non_fatally() {
        let mut registry = test_populated_registry(1);
        let mut applicator = Applicator::new(&mut registry);

        let event = || {
            (
                SMId::Deposit(0),
                SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
                    block_height: INITIAL_BLOCK_HEIGHT + 1,
                }))),
            )
        };

        applicator.apply_batch(vec![event()]).unwrap();
        // Same height again — duplicate, should not fail
        applicator.apply_batch(vec![event()]).unwrap();

        let (_, tracker) = applicator.finish();
        assert!(!tracker.into_batches().is_empty());
    }

    // ===== Registry access between batches =====

    #[test]
    fn registry_reflects_settled_state_between_batches() {
        let mut registry = test_populated_registry(1);
        let mut applicator = Applicator::new(&mut registry);

        assert_eq!(applicator.registry().num_deposits(), 1);
        assert_eq!(
            applicator.registry().get_graph_ids().len(),
            N_TEST_OPERATORS
        );

        applicator
            .apply_batch(vec![(
                SMId::Deposit(0),
                SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
                    block_height: INITIAL_BLOCK_HEIGHT + 1,
                }))),
            )])
            .unwrap();

        // Registry still accessible and consistent after batch
        assert_eq!(applicator.registry().num_deposits(), 1);
    }
}
