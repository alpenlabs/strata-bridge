//! The main event loop that wires all pipeline stages together:
//! `EventsMux` → classify → process → signal cascade → persist → dispatch.

use std::collections::{BTreeMap, VecDeque};

use bitcoin::{
    OutPoint,
    hashes::{Hash, sha256},
};
use strata_bridge_db2::traits::BridgeDb;
use strata_bridge_primitives::operator_table::OperatorTable;
use tracing::{info, warn};

use crate::{
    duty_dispatcher::DutyDispatcher,
    errors::{PipelineError, ProcessError},
    events_classifier::{offchain, onchain},
    events_mux::{EventsMux, UnifiedEvent},
    events_router,
    persister::{PersistenceTracker, Persister},
    signals_router,
    sm_registry::SMRegistry,
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// The main pipeline that drives the orchestrator.
///
/// Continuously pulls events from the multiplexer, classifies and routes them to state machines,
/// processes them through the STF, cascades any resulting signals, persists state changes, and
/// dispatches duties to executors.
#[expect(missing_debug_implementations)]
pub struct Pipeline<Db: BridgeDb> {
    event_mux: EventsMux,
    registry: SMRegistry,
    persister: Persister<Db>,
    dispatcher: DutyDispatcher,
}

impl<Db: BridgeDb> Pipeline<Db> {
    /// Creates a new pipeline with all required components.
    pub const fn new(
        event_mux: EventsMux,
        registry: SMRegistry,
        persister: Persister<Db>,
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
    pub async fn run(
        mut self,
        initial_operator_table: OperatorTable,
    ) -> Result<(), PipelineError<Db>> {
        loop {
            // Stage 1: Multiplex event streams
            let event = self.event_mux.next().await;

            // Handle non-routable events (consume `event` on early exit, rebind otherwise)
            let event = match event {
                UnifiedEvent::Shutdown(sender) => {
                    info!("received shutdown signal, draining registry");
                    let _ = sender.send(());
                    return Ok(());
                }

                // Routable events — pass through to the classification stage
                routable => routable,
            };

            let (stake_outpoints, unstaking_images) =
                get_mocked_stake_data(&initial_operator_table);

            // Stage 2: Classification
            let (targets, new_duties): (Vec<(SMId, SMEvent)>, Vec<UnifiedDuty>) = match &event {
                UnifiedEvent::Block(block_event) => onchain::classify_block(
                    &initial_operator_table,
                    stake_outpoints,
                    unstaking_images,
                    &mut self.registry,
                    block_event,
                ),

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
            for batch in tracker.into_batches() {
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
    ) -> Result<(Vec<crate::sm_types::UnifiedDuty>, PersistenceTracker), PipelineError<Db>> {
        let mut all_duties = Vec::new();
        let mut signal_queue: VecDeque<(SMId, SMEvent)> = VecDeque::new();
        let mut tracker = PersistenceTracker::new();

        // Process initial targets
        for (sm_id, sm_event) in targets {
            self.process_signal(
                sm_id,
                sm_event,
                &mut all_duties,
                &mut signal_queue,
                &mut tracker,
            )?;
        }

        // Signal cascade: process signals until the queue is drained
        while let Some((sm_id, sm_event)) = signal_queue.pop_front() {
            self.process_signal(
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
    /// `DuplicateEvent` errors are non-fatal (logged and skipped). All other errors are fatal.
    fn process_signal(
        &mut self,
        sm_id: SMId,
        sm_event: SMEvent,
        all_duties: &mut Vec<crate::sm_types::UnifiedDuty>,
        signal_queue: &mut VecDeque<(SMId, SMEvent)>,
        tracker: &mut PersistenceTracker,
    ) -> Result<(), PipelineError<Db>> {
        match self.registry.process_event(&sm_id, sm_event) {
            Ok(output) => {
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
            // Duplicate events are non-fatal (can happen due to network retransmission)
            Err(ProcessError::DuplicateEvent(id, event)) => {
                warn!(?id, %event, "duplicate event, skipping");
                Ok(())
            }
            // Event rejections are non-fatal (can happen if the event is no longer relevant, e.g.
            // due to another input beating it to the punch)
            Err(ProcessError::EventRejected(id, event, reason)) => {
                warn!(?id, %event, %reason, "event rejected by state machine, skipping");
                Ok(())
            }
            // All other processing errors are fatal
            Err(e) => Err(e.into()),
        }
    }
}

/// Generates mocked stake data for the given operator table.
fn get_mocked_stake_data(
    initial_operator_table: &OperatorTable,
) -> (BTreeMap<u32, OutPoint>, BTreeMap<u32, sha256::Hash>) {
    // TODO: (@Rajil1213) query Operator and Stake SMs for operator table and stake data
    // For now, use static values.

    let mock_outpoint = OutPoint::default(); // dummy outpoint
    let stake_outpoints = initial_operator_table
        .operator_idxs()
        .into_iter()
        .map(|idx| (idx, mock_outpoint))
        .collect();

    let mock_hash = sha256::Hash::from_slice(&[0u8; 32]).expect("dummy hash must be valid");
    let unstaking_images = initial_operator_table
        .operator_idxs()
        .into_iter()
        .map(|idx| (idx, mock_hash))
        .collect();
    // dummy stake images
    (stake_outpoints, unstaking_images)
}
