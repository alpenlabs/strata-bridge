//! The main event loop that wires all pipeline stages together:
//! `EventsMux` → classify → process → signal cascade → persist → dispatch.

use std::collections::VecDeque;

use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_sm::graph::{
    duties::GraphDuty,
    events::{AdaptorsVerifiedEvent, GraphEvent},
};
use tracing::{info, trace, warn};

use crate::{
    duty_dispatcher::DutyDispatcher,
    errors::PipelineError,
    events_classifier::{offchain, onchain},
    events_mux::{EventsMux, UnifiedEvent},
    events_router,
    persister::{PersistenceTracker, Persister},
    signals_router,
    sm_registry::{IgnoredEventReason, ProcessOutcome, SMRegistry},
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// The main pipeline that drives the orchestrator.
///
/// Continuously pulls events from the multiplexer, classifies and routes them to state machines,
/// processes them through the STF, cascades any resulting signals, persists state changes, and
/// dispatches duties to executors.
#[expect(missing_debug_implementations)]
pub struct Pipeline {
    event_mux: EventsMux,
    registry: SMRegistry,
    persister: Persister,
    dispatcher: DutyDispatcher,
}

impl Pipeline {
    /// Creates a new pipeline with all required components.
    pub const fn new(
        event_mux: EventsMux,
        registry: SMRegistry,
        persister: Persister,
        dispatcher: DutyDispatcher,
    ) -> Self {
        Self {
            event_mux,
            registry,
            persister,
            dispatcher,
        }
    }

    /// Runs the main event loop until shutdown.
    ///
    /// On shutdown, sends the signal through the oneshot channel and returns.
    ///
    /// The `initial_operator_table` needs to be constructed from a params file or similar source of
    /// truth for now. Eventually, this will be queried from the Operator State Machine in the
    /// registry.
    pub async fn run(mut self, initial_operator_table: OperatorTable) -> Result<(), PipelineError> {
        loop {
            // Stage 1: Multiplex event streams
            let event = self.event_mux.next().await;
            trace!(?event, "received new event from multiplexer");

            // Handle non-routable events (consume `event` on early exit, rebind otherwise)
            let event = match event {
                UnifiedEvent::Shutdown => {
                    info!("received shutdown signal, breaking out of event loop");
                    return Ok(());
                }

                // Routable events — pass through to the classification stage
                routable => routable,
            };

            // Stage 2: Classification
            trace!(
                ?event,
                "classifying event and determining target state machines"
            );
            let (targets, new_duties): (Vec<(SMId, SMEvent)>, Vec<UnifiedDuty>) = match &event {
                UnifiedEvent::Block(block_event) => onchain::classify_block(
                    &initial_operator_table,
                    &mut self.registry,
                    block_event,
                )?,

                _ => {
                    // P2P / assignment / ticks: route to SM ids, then classify each
                    let sm_ids = events_router::route(&event, &self.registry);
                    (
                        sm_ids
                            .into_iter()
                            .filter_map(|sm_id| {
                                offchain::classify(&sm_id, &event, &self.registry)
                                    .map(|sm_event| (sm_id, sm_event))
                            })
                            .collect(),
                        Vec::new(),
                    )
                }
            };

            // Stages 3+4: Process targets + signal cascade
            let (mut all_duties, tracker) = self.process_and_cascade(targets)?;
            all_duties.extend(new_duties);

            // Stage 5: Batch persistence

            let batches = tracker.into_batches();
            info!(count=%batches.len(), "persisting updated state machines batches");
            for batch in batches {
                self.persister.persist_batch(batch, &self.registry).await?;
            }

            // Stage 6: Dispatch duties
            for duty in all_duties {
                self.dispatcher.dispatch(duty).await;
            }
        }
    }

    /// Processes all targets through the STF and cascades any resulting signals until the signal
    /// queue is drained.
    ///
    /// Returns the accumulated duties and the persistence tracker recording which SMs were touched.
    fn process_and_cascade(
        &mut self,
        targets: Vec<(SMId, SMEvent)>,
    ) -> Result<(Vec<crate::sm_types::UnifiedDuty>, PersistenceTracker), PipelineError> {
        let mut all_duties = Vec::new();
        let mut signal_queue: VecDeque<(SMId, SMEvent)> = VecDeque::new();
        let mut tracker = PersistenceTracker::new();

        // Process initial targets
        for (sm_id, sm_event) in targets {
            self.process_event(
                sm_id,
                sm_event,
                &mut all_duties,
                &mut signal_queue,
                &mut tracker,
            )?;
        }

        all_duties
            .iter()
            .filter_map(|duty| {
                if let UnifiedDuty::Graph(GraphDuty::VerifyAdaptors { graph_idx, .. }) = duty {
                    Some((
                        *graph_idx,
                        GraphEvent::AdaptorsVerified(AdaptorsVerifiedEvent {}),
                    ))
                } else {
                    None
                }
            })
            .for_each(|(graph_idx, event)| {
                info!(%graph_idx, "enqueuing fabricated AdaptorsVerified event");

                signal_queue.push_back((graph_idx.into(), event.into()));
            });

        // Signal cascade: process signals until the queue is drained
        while let Some((sm_id, sm_event)) = signal_queue.pop_front() {
            self.process_event(
                sm_id,
                sm_event,
                &mut all_duties,
                &mut signal_queue,
                &mut tracker,
            )?;
        }

        Ok((all_duties, tracker))
    }

    /// Processes a single (SMId, SMEvent) pair through the registry's STF.
    ///
    /// On success, accumulates duties and enqueues any signal-derived events.
    /// Ignored outcomes are non-fatal (logged and skipped). Fatal errors are propagated.
    fn process_event(
        &mut self,
        sm_id: SMId,
        sm_event: SMEvent,
        all_duties: &mut Vec<crate::sm_types::UnifiedDuty>,
        signal_queue: &mut VecDeque<(SMId, SMEvent)>,
        tracker: &mut PersistenceTracker,
    ) -> Result<(), PipelineError> {
        match self.registry.process_event(&sm_id, sm_event) {
            Ok(ProcessOutcome::Applied(output)) => {
                all_duties.extend(output.duties);
                tracker.record(sm_id);

                for signal in output.signals {
                    for (target_id, target_event) in
                        signals_router::route_signal(&self.registry, signal)
                    {
                        tracker.link(sm_id, target_id);
                        signal_queue.push_back((target_id, target_event));
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
