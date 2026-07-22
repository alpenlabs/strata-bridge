//! The main event loop that wires all pipeline stages together:
//! `EventsMux` → classify → `Applicator::apply_batch` → persist → dispatch.

use std::{collections::BTreeSet, time::Instant};

use strata_bridge_primitives::{operator_table::OperatorTable, types::BitcoinBlockHeight};
use strata_bridge_sm::stake::{context::StakeSMCtx, machine::StakeSM};
use tracing::{Instrument, debug, error, info, info_span, trace, warn};

use crate::{
    applicator::Applicator,
    duty_dispatcher::DutyDispatcher,
    errors::{PipelineError, ProcessError},
    events_classifier::{offchain, onchain},
    events_mux::{EventsMux, UnifiedEvent},
    events_router, observability,
    persister::Persister,
    sm_registry::SMRegistry,
    sm_types::{SMId, UnifiedDuty},
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
    ///
    /// Before entering the main event loop, this method bootstraps one [`StakeSM`] per operator in
    /// the `initial_operator_table`. Any stake SMs already recovered from the database are
    /// preserved; only missing ones are created. The `start_height` is used as the initial block
    /// height for newly created stake SMs (typically the chain tip or the persisted cursor).
    pub async fn run(
        self,
        initial_operator_table: OperatorTable,
        start_height: BitcoinBlockHeight,
    ) -> Result<(), PipelineError> {
        self.run_with_observer(initial_operator_table, start_height, || {})
            .await
    }

    /// Runs the main event loop and calls `on_event` after each non-shutdown event is received.
    pub async fn run_with_observer(
        mut self,
        initial_operator_table: OperatorTable,
        start_height: BitcoinBlockHeight,
        mut on_event: impl FnMut(),
    ) -> Result<(), PipelineError> {
        observability::describe_metrics();
        if let Err(error) = self
            .bootstrap_stake_sms(&initial_operator_table, start_height)
            .instrument(info_span!("bridge_stake_bootstrap"))
            .await
        {
            error!(%error, "failed to bootstrap stake state machines");
            return Err(error);
        }

        loop {
            // Stage 1: Multiplex event streams
            let event = self.event_mux.next().await;
            let event_kind = observability::unified_event_kind(&event);
            let started = Instant::now();
            observability::record_pipeline_event_received(event_kind);

            // Handle non-routable events (consume `event` on early exit, rebind otherwise)
            let event = match event {
                UnifiedEvent::Shutdown => {
                    // No duration sample: a one-off shutdown latency series has no analytical
                    // value. The ingress counter above still records that shutdown arrived.
                    info!("received shutdown signal, breaking out of event loop");
                    return Ok(());
                }

                // Routable events — pass through to the classification stage
                routable => routable,
            };
            on_event();

            let span = info_span!(
                "bridge_event",
                event_kind,
                result = tracing::field::Empty,
                error_class = tracing::field::Empty,
            );
            let outcome = self
                .process_routable_event(&initial_operator_table, event, event_kind)
                .instrument(span.clone())
                .await;

            match outcome {
                Ok(()) => {
                    span.record("result", "success");
                    span.record("error_class", "none");
                    observability::record_pipeline_event_finished(
                        event_kind,
                        "success",
                        "none",
                        started.elapsed(),
                    );
                }
                Err(processing_error) => {
                    let error_class = observability::pipeline_error_class(&processing_error);
                    span.record("result", "error");
                    span.record("error_class", error_class);
                    observability::record_pipeline_event_finished(
                        event_kind,
                        "error",
                        error_class,
                        started.elapsed(),
                    );
                    error!(
                        parent: &span,
                        error = %processing_error,
                        error_class,
                        event_kind,
                        "bridge event processing failed"
                    );
                    return Err(processing_error);
                }
            }
        }
    }

    async fn process_routable_event(
        &mut self,
        initial_operator_table: &OperatorTable,
        event: UnifiedEvent,
        event_kind: &'static str,
    ) -> Result<(), PipelineError> {
        trace!(?event, "processing routable event");

        // Stage 2+3: Classify and process through Applicator.
        let mut applicator = Applicator::new(&mut self.registry);

        match &event {
            UnifiedEvent::Block(block_event) => {
                onchain::process_block(&mut applicator, initial_operator_table, block_event)?;
            }
            UnifiedEvent::Shutdown => {
                error!("shutdown event reached the routable-event pipeline");
                return Err(PipelineError::InternalInvariant(
                    "shutdown event reached routable-event processing",
                ));
            }
            _ => {
                let routing_started = Instant::now();
                trace!(
                    ?event,
                    "classifying event and determining target state machines"
                );
                let sm_ids = events_router::route(&event, applicator.registry());
                let target_count = sm_ids.len();
                let seed_events: Vec<_> = sm_ids
                    .into_iter()
                    .filter_map(|sm_id| {
                        offchain::classify(&sm_id, &event, applicator.registry())
                            .map(|sm_event| (sm_id, sm_event))
                    })
                    .collect();
                let classified_count = seed_events.len();
                let routing_result = if target_count == 0 {
                    "no_targets"
                } else if classified_count == 0 {
                    "no_classification"
                } else {
                    "classified"
                };
                observability::record_routing(
                    event_kind,
                    routing_result,
                    routing_started.elapsed(),
                );

                if target_count == 0
                    && !matches!(&event, UnifiedEvent::NagTick | UnifiedEvent::RetryTick)
                {
                    // Provisional level: a routing miss drops the event and relies on nag-based
                    // recovery, which makes it worth surfacing, but gossip about a state machine
                    // this operator has not created yet may be a normal transient. Revisit the
                    // level once staging traffic quantifies the noise.
                    warn!(event_kind, "event did not route to any state machine");
                } else if target_count > 0 && classified_count == 0 {
                    warn!(
                        event_kind,
                        target_count,
                        "event routed but did not classify into a state-machine event"
                    );
                }

                applicator.apply_batch(seed_events)?;
            }
        }

        let (all_duties, tracker) = applicator.finish();

        // Stage 4: Batch persistence.
        let batches = tracker.into_batches();
        if batches.is_empty() {
            debug!(
                duty_count = all_duties.len(),
                "event produced no state-machine updates requiring persistence"
            );
        } else {
            info!(
                batch_count = batches.len(),
                duty_count = all_duties.len(),
                "persisting state-machine updates before duty dispatch"
            );
        }
        for batch in batches {
            self.persister.persist_batch(batch, &self.registry).await?;
        }

        // Stage 5: Dispatch duties only after every state update is durable.
        for duty in all_duties {
            self.dispatcher.dispatch(duty);
        }

        Ok(())
    }

    /// Creates one stake state machine per operator in `operator_table` that does not yet exist in
    /// the registry. Persists the newly created machines and dispatches any constructor duties
    /// (only the POV operator's SSM emits `PublishStakeData`).
    async fn bootstrap_stake_sms(
        &mut self,
        operator_table: &OperatorTable,
        start_height: BitcoinBlockHeight,
    ) -> Result<(), PipelineError> {
        let mut touched: BTreeSet<SMId> = BTreeSet::new();
        let mut duties: Vec<UnifiedDuty> = Vec::new();

        for op_idx in operator_table.operator_idxs() {
            if self.registry.contains_id(&SMId::Stake(op_idx)) {
                continue;
            }

            let ctx = StakeSMCtx::new(op_idx, operator_table.clone());
            let (ssm, initial_duty) = StakeSM::new(ctx, start_height);
            self.registry
                .insert_stake(op_idx, ssm)
                .map_err(ProcessError::from)?;
            touched.insert(SMId::Stake(op_idx));
            info!(%op_idx, %start_height, "bootstrapped stake state machine");

            if let Some(duty) = initial_duty {
                duties.push(duty.into());
            }
        }

        if !touched.is_empty() {
            self.persister
                .persist_batch(touched, &self.registry)
                .await?;
        }
        for duty in duties {
            self.dispatcher.dispatch(duty);
        }

        Ok(())
    }
}
