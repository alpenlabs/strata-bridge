//! The main event loop that wires all pipeline stages together:
//! `EventsMux` → classify → `Applicator::apply_batch` → persist → dispatch.

use strata_bridge_primitives::operator_table::OperatorTable;
use tracing::{info, trace};

use crate::{
    applicator::Applicator,
    duty_dispatcher::DutyDispatcher,
    errors::PipelineError,
    events_classifier::{offchain, onchain},
    events_mux::{EventsMux, UnifiedEvent},
    events_router,
    persister::Persister,
    sm_registry::SMRegistry,
};

/// The main pipeline that drives the orchestrator.
///
/// Continuously pulls events from the multiplexer, classifies and routes them to state machines,
/// processes them through the [`Applicator`], persists state changes, and dispatches duties to
/// executors.
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

            // Stage 2+3: Classify and process through Applicator
            let mut applicator = Applicator::new(&mut self.registry);

            match &event {
                UnifiedEvent::Block(block_event) => {
                    onchain::process_block(&mut applicator, &initial_operator_table, block_event)?;
                }

                _ => {
                    // P2P / assignment / ticks: route to SM ids, then classify each
                    trace!(
                        ?event,
                        "classifying event and determining target state machines"
                    );
                    let sm_ids = events_router::route(&event, applicator.registry());
                    let seed_events: Vec<_> = sm_ids
                        .into_iter()
                        .filter_map(|sm_id| {
                            offchain::classify(&sm_id, &event, applicator.registry())
                                .map(|sm_event| (sm_id, sm_event))
                        })
                        .collect();

                    applicator.apply_batch(seed_events)?;
                }
            }

            let (all_duties, tracker) = applicator.finish();

            // Stage 4: Batch persistence
            let batches = tracker.into_batches();
            info!(count=%batches.len(), "persisting updated state machines batches");
            for batch in batches {
                self.persister.persist_batch(batch, &self.registry).await?;
            }

            // Stage 5: Dispatch duties
            for duty in all_duties {
                self.dispatcher.dispatch(duty);
            }
        }
    }
}
