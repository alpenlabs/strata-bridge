//! The main event loop that wires all pipeline stages together:
//! `EventsMux` → classify → `Applicator::apply_batch` → persist → dispatch.

use std::{collections::BTreeSet, time::Instant};

use strata_bridge_p2p_types::UnsignedGossipsubMsg;
use strata_bridge_primitives::{operator_table::OperatorTable, types::BitcoinBlockHeight};
use strata_bridge_sm::stake::{context::StakeSMCtx, machine::StakeSM};
use tracing::{Instrument, debug, error, info, info_span, trace, warn};

use crate::{
    applicator::Applicator,
    duty_dispatcher::DutyDispatcher,
    errors::{PipelineError, ProcessError},
    events_classifier::{offchain, onchain},
    events_mux::{EventsMux, SafeHarbourEvent, UnifiedEvent},
    events_router, observability,
    persister::{PersistenceTracker, Persister},
    safe_harbour_scan::safe_harbour_scan,
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
    ///
    /// When a persisted safe-harbour latch is recovered, the sweep/abort scan is also seeded once
    /// before the loop.
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

        // A recovered latch may cover deposits that were never scanned, and no buried block is
        // guaranteed to arrive to retry: seed sweeps and aborts once before the loop.
        if self.registry.safe_harbour_active() {
            info!("recovered an active safe-harbour latch; seeding the sweep/abort scan");
            let mut applicator = Applicator::new(&mut self.registry);
            apply_safe_harbour_scan(&mut applicator)?;
            let (duties, tracker) = applicator.finish();
            self.persist_batches(tracker).await?;
            self.dispatch_duties(duties);
        }

        loop {
            // Stage 1: Multiplex event streams
            let event = self.event_mux.next().await;

            // Handle non-routable events (consume `event` on early exit, rebind otherwise)
            let event = match event {
                UnifiedEvent::Shutdown => {
                    info!("received shutdown signal, breaking out of event loop");
                    return Ok(());
                }

                // Routable events — pass through to the classification stage
                routable => routable,
            };
            let event_kind = observability::unified_event_kind(&event);
            let started = Instant::now();
            on_event();

            let span = info_span!(
                "bridge_event",
                event_kind,
                result = tracing::field::Empty,
                error_class = tracing::field::Empty,
            );
            let outcome = async {
                trace!(?event, "processing routable event");

                // Safe harbour is registry-level, not SM-scoped: latch and persist it before
                // borrowing the registry for the applicator. Only a first latch proceeds to the
                // scan below; replayed activations from the monotonic feed are skipped.
                if let UnifiedEvent::SafeHarbour(safe_harbour) = &event
                    && !self.process_safe_harbour(safe_harbour.clone()).await?
                {
                    return Ok::<(), PipelineError>(());
                }

                // Stage 2+3: Classify and process through Applicator.
                let mut applicator = Applicator::new(&mut self.registry);

                match &event {
                    // On first latch: sweep and abort immediately rather than waiting for the next
                    // buried block.
                    UnifiedEvent::SafeHarbour(_) => apply_safe_harbour_scan(&mut applicator)?,

                    UnifiedEvent::Block(block_event) => {
                        onchain::process_block(
                            &mut applicator,
                            &initial_operator_table,
                            block_event,
                        )?;

                        // While safe harbour is active, drive sweeps and aborts from the post-block
                        // deposit states; the per-block replay is the retry mechanism.
                        apply_safe_harbour_scan(&mut applicator)?;
                    }
                    _ => {
                        trace!(
                            ?event,
                            "classifying event and determining target state machines"
                        );
                        let sm_ids = events_router::route(&event, applicator.registry());
                        let target_count = sm_ids.len();
                        let mut expected_drop_count = 0;
                        let seed_events: Vec<_> = sm_ids
                            .into_iter()
                            .filter_map(|sm_id| {
                                match offchain::classify_routed(
                                    &sm_id,
                                    &event,
                                    applicator.registry(),
                                ) {
                                    offchain::ClassificationOutcome::Classified(sm_event) => {
                                        Some((sm_id, sm_event))
                                    }
                                    offchain::ClassificationOutcome::ExpectedDrop => {
                                        expected_drop_count += 1;
                                        None
                                    }
                                    offchain::ClassificationOutcome::Unclassified => None,
                                }
                            })
                            .collect();
                        let classified_count = seed_events.len();
                        let routing_result =
                            routing_result(target_count, classified_count, expected_drop_count);
                        observability::record_routing(event_kind, routing_result);

                        if target_count == 0
                            && !matches!(&event, UnifiedEvent::NagTick | UnifiedEvent::RetryTick)
                        {
                            debug!(event_kind, "event did not route to any state machine");
                        } else if should_warn_on_unclassified_event(
                            &event,
                            target_count,
                            classified_count,
                        ) {
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
                self.persist_batches(tracker).await?;

                // Stage 5: Dispatch duties after persistence, suppressing withdrawal-path duties
                // while safe harbour is active.
                self.dispatch_duties(all_duties);

                Ok::<(), PipelineError>(())
            }
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

    /// Latches and persists a safe-harbour activation, returning whether this call latched.
    ///
    /// Idempotent and monotonic: only the first activation latches, persists the frozen address
    /// (so the latch survives a restart), and logs. Subsequent activations — including re-emitted
    /// ones from the monotonic feed — are no-ops. Non-activation observations are ignored, so a
    /// tip reorg that flips the ASM flag back to inactive never un-latches the node.
    async fn process_safe_harbour(
        &mut self,
        event: SafeHarbourEvent,
    ) -> Result<bool, PipelineError> {
        if !event.activated {
            return Ok(false);
        }
        let Some(address) = event.address else {
            warn!("ASM reported safe harbour active without an address; ignoring");
            return Ok(false);
        };

        if !self.registry.activate_safe_harbour(address.clone()) {
            return Ok(false);
        }

        info!("safe harbour activated; latching frozen address and halting new custody");
        self.persister.persist_safe_harbour(&address).await?;
        Ok(true)
    }

    /// Persists the batches of state machines touched during event processing.
    async fn persist_batches(&self, tracker: PersistenceTracker) -> Result<(), PipelineError> {
        let batches = tracker.into_batches();
        info!(count=%batches.len(), "persisting updated state machines batches");
        for batch in batches {
            self.persister.persist_batch(batch, &self.registry).await?;
        }
        Ok(())
    }

    /// Dispatches duties, dropping the suppressed ones while safe harbour is active.
    fn dispatch_duties(&self, duties: Vec<UnifiedDuty>) {
        let safe_harbour_active = self.registry.safe_harbour_active();
        for duty in duties {
            // While safe harbour is active no withdrawal advances:
            // the withdrawal-path duties are dropped here, which also covers the graph SMs and
            // the switch-over window before a deposit enters the sweep flow.
            // Defensive duties (contest, counterproof, slash, unstaking burn) always dispatch
            if safe_harbour_active && duty.should_suppress_under_safe_harbour() {
                info!(
                    ?duty,
                    "safe harbour active; suppressing withdrawal-path duty"
                );
                continue;
            }
            self.dispatcher.dispatch(duty);
        }
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

/// Seeds the safe-harbour sweep/abort scan through the applicator; a no-op while the latch is
/// unset.
fn apply_safe_harbour_scan(applicator: &mut Applicator<'_>) -> Result<(), PipelineError> {
    let scan_events = safe_harbour_scan(applicator.registry());
    if !scan_events.is_empty() {
        info!(count = %scan_events.len(), "seeding safe-harbour sweep/abort events");
        applicator.apply_batch(scan_events)?;
    }
    Ok(())
}

const fn routing_result(
    target_count: usize,
    classified_count: usize,
    expected_drop_count: usize,
) -> &'static str {
    if target_count == 0 {
        "no_targets"
    } else if classified_count > 0 {
        "classified"
    } else if expected_drop_count == target_count {
        "expected_drop"
    } else {
        "no_classification"
    }
}

/// Returns whether an event that produced no state-machine event needs the pipeline's generic
/// warning. Nag requests report their specific drop reason in the router or classifier, so another
/// warning here would either be misleading for an expected wrong-recipient drop or duplicate a
/// more useful warning.
const fn should_warn_on_unclassified_event(
    event: &UnifiedEvent,
    target_count: usize,
    classified_count: usize,
) -> bool {
    target_count > 0 && classified_count == 0 && !is_nag_request(event)
}

const fn is_nag_request(event: &UnifiedEvent) -> bool {
    match event {
        UnifiedEvent::OuroborosMessage(message) => matches!(
            &message.publish,
            UnsignedGossipsubMsg::NagRequestExchange(_)
        ),
        UnifiedEvent::GossipMessage(message) => matches!(
            &message.unsigned,
            UnsignedGossipsubMsg::NagRequestExchange(_)
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use strata_bridge_p2p_service::message_handler::OuroborosMessage;
    use strata_bridge_p2p_types::{
        GossipsubMsg, NagRequest, NagRequestPayload, UnsignedGossipsubMsg,
    };
    use strata_bridge_sm::deposit::state::DepositState;

    use super::*;
    use crate::testing::{test_populated_registry, test_safe_harbour_address};

    fn nag_request() -> UnsignedGossipsubMsg {
        UnsignedGossipsubMsg::NagRequestExchange(NagRequest {
            recipient: vec![0; 32].into(),
            payload: NagRequestPayload::DepositNonce { deposit_idx: 0 },
        })
    }

    #[test]
    fn scan_helper_is_a_noop_while_not_latched() {
        let mut registry = test_populated_registry(1);
        let mut applicator = Applicator::new(&mut registry);

        apply_safe_harbour_scan(&mut applicator).unwrap();

        let (duties, tracker) = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
    }

    #[test]
    fn scan_helper_applies_transitions_on_a_latched_registry() {
        let mut registry = test_populated_registry(1);
        registry.activate_safe_harbour(test_safe_harbour_address());
        let mut applicator = Applicator::new(&mut registry);

        apply_safe_harbour_scan(&mut applicator).unwrap();

        // The populated registry's deposit sits in the safe window (`Created`), so seeding the
        // scan must abort it, not just enumerate it.
        assert_eq!(
            applicator
                .registry()
                .get_deposit(&0)
                .expect("deposit SM must exist")
                .state(),
            &DepositState::Aborted,
        );

        let (_, tracker) = applicator.finish();
        assert!(
            !tracker.into_batches().is_empty(),
            "scan-seeded transitions must be tracked for persistence"
        );
    }

    #[test]
    fn unclassified_peer_nag_does_not_emit_generic_warning() {
        let event = UnifiedEvent::GossipMessage(GossipsubMsg {
            signature: Vec::new(),
            key: vec![1; 32].into(),
            unsigned: nag_request(),
        });

        assert!(!should_warn_on_unclassified_event(&event, 1, 0));
    }

    #[test]
    fn unclassified_ouroboros_nag_does_not_emit_generic_warning() {
        let event = UnifiedEvent::OuroborosMessage(OuroborosMessage {
            publish: nag_request(),
        });

        assert!(!should_warn_on_unclassified_event(&event, 1, 0));
    }

    #[test]
    fn other_unclassified_routed_events_still_emit_generic_warning() {
        assert!(should_warn_on_unclassified_event(
            &UnifiedEvent::NagTick,
            1,
            0
        ));
    }

    #[test]
    fn classified_or_unrouted_events_do_not_emit_generic_warning() {
        let event = UnifiedEvent::NagTick;

        assert!(!should_warn_on_unclassified_event(&event, 1, 1));
        assert!(!should_warn_on_unclassified_event(&event, 0, 0));
    }

    #[test]
    fn routing_result_separates_expected_drops_from_failures() {
        assert_eq!(routing_result(0, 0, 0), "no_targets");
        assert_eq!(routing_result(1, 1, 0), "classified");
        assert_eq!(routing_result(1, 0, 1), "expected_drop");
        assert_eq!(routing_result(1, 0, 0), "no_classification");
        assert_eq!(routing_result(2, 0, 1), "no_classification");
    }
}
