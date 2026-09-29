//! The main event loop that wires all pipeline stages together:
//! `EventsMux` → classify → `Applicator::apply_batch` → persist → dispatch.

use std::time::Instant;

use btc_tracker::event::BlockEvent;
use strata_bridge_p2p_types::UnsignedGossipsubMsg;
use strata_bridge_primitives::{
    covenant::CovenantId,
    operator_set_schedule::OperatorSetSchedule,
    operator_table::OperatorTable,
    types::{BitcoinBlockHeight, OperatorIdx},
};
use tracing::{Instrument, debug, error, info, info_span, trace, warn};

use crate::{
    applicator::{Applicator, BatchOutput},
    duty_dispatcher::DutyDispatcher,
    errors::PipelineError,
    events_classifier::{offchain, onchain},
    events_mux::{EventsMux, SafeHarbourEvent, UnifiedEvent},
    events_router, observability,
    persister::Persister,
    safe_harbour_scan::safe_harbour_scan,
    sm_registry::SMRegistry,
    sm_types::UnifiedDuty,
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
    /// Before entering the main event loop, this method bootstraps one
    /// [`StakeSM`](strata_bridge_sm::stake::machine::StakeSM) per operator in
    /// the `initial_operator_table`. Any stake SMs already recovered from the database are
    /// preserved; only missing ones are created. The `start_height` is used as the initial block
    /// height for newly created stake SMs (typically the chain tip or the persisted cursor).
    /// `activation_height` is the configured admin boundary, independent of that cursor.
    ///
    /// When a persisted safe-harbour latch is recovered, the sweep/abort scan is also seeded once
    /// before the loop.
    pub async fn run(
        self,
        initial_operator_table: OperatorTable,
        registrations: OperatorSetSchedule,
        start_height: BitcoinBlockHeight,
        activation_height: BitcoinBlockHeight,
    ) -> Result<(), PipelineError> {
        self.run_with_observer(
            initial_operator_table,
            registrations,
            start_height,
            activation_height,
            || {},
        )
        .await
    }

    /// Runs the main event loop and calls `on_event` after each non-shutdown event is received.
    pub async fn run_with_observer(
        mut self,
        initial_operator_table: OperatorTable,
        registrations: OperatorSetSchedule,
        start_height: BitcoinBlockHeight,
        activation_height: BitcoinBlockHeight,
        mut on_event: impl FnMut(),
    ) -> Result<(), PipelineError> {
        // TODO: <https://alpenlabs.atlassian.net/browse/STR-4398>
        // Resolve each block's covenant/table through STR-3670's local history lookup and
        // integrate that context with registration, canonical indexing, and readiness.
        let covenant = CovenantId::from_operator_table(&initial_operator_table, activation_height)
            .expect("validated initial operator table");
        observability::describe_metrics();
        if let Err(error) = self
            .bootstrap_membership(
                registrations,
                initial_operator_table.pov_idx(),
                start_height,
            )
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
            let mut applicator =
                Applicator::new(&mut self.registry, Some(initial_operator_table.pov_idx()));
            apply_safe_harbour_scan(&mut applicator)?;
            let batch = applicator.finish();
            self.commit_batch(batch).await?;
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

                if let UnifiedEvent::Block(block_event) = &event {
                    let batch = process_block(
                        &mut self.registry,
                        &initial_operator_table,
                        covenant,
                        block_event,
                    )?;
                    self.commit_batch(batch).await?;
                    return Ok(());
                }

                // Stage 2+3: Classify and process through Applicator.
                let mut applicator =
                    Applicator::new(&mut self.registry, Some(initial_operator_table.pov_idx()));

                match &event {
                    // On first latch: sweep and abort immediately rather than waiting for the next
                    // buried block.
                    UnifiedEvent::SafeHarbour(_) => apply_safe_harbour_scan(&mut applicator)?,

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

                let batch = applicator.finish();
                self.commit_batch(batch).await?;

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

    /// Persists all causal groups before dispatching any duties.
    /// If persistence fails, no duties are dispatched.
    async fn commit_batch(&self, batch: BatchOutput) -> Result<(), PipelineError> {
        self.persister
            .persist_batches(batch.tracker, &self.registry)
            .await?;
        self.dispatch_duties(batch.duties);
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

    /// Initializes and persists membership and missing stakes before dispatching their duties.
    async fn bootstrap_membership(
        &mut self,
        registrations: OperatorSetSchedule,
        local_operator: OperatorIdx,
        start_height: BitcoinBlockHeight,
    ) -> Result<(), PipelineError> {
        let height = self.registry.latest_gate_height().unwrap_or(start_height);
        let mut applicator = Applicator::new(&mut self.registry, Some(local_operator));
        applicator.initialize_operator_set(registrations, height)?;
        let batch = applicator.finish();
        self.commit_batch(batch).await
    }
}

/// Applies both block passes and returns their accumulated changes and duties.
pub(super) fn process_block(
    registry: &mut SMRegistry,
    operator_table: &OperatorTable,
    covenant: CovenantId,
    block_event: &BlockEvent,
) -> Result<BatchOutput, PipelineError> {
    let height = block_event
        .block
        .bip34_block_height()
        .expect("valid block height");

    let gate_height = registry.latest_gate_height();

    // Older replayed blocks must not register deposits using later membership/stake state.
    // Reaching the gate permits admission checks; it does not establish deposit readiness.
    let block_reaches_gate = gate_height.is_none_or(|gate| height >= gate);

    let mut applicator = Applicator::new(registry, Some(operator_table.pov_idx()));

    onchain::process_stake_pass(&mut applicator, block_event)?;
    onchain::process_deposit_graph_pass(
        &mut applicator,
        operator_table,
        covenant,
        block_reaches_gate,
        block_event,
    )?;

    apply_safe_harbour_scan(&mut applicator)?;

    Ok(applicator.finish())
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
        let mut applicator = Applicator::new(&mut registry, None);

        apply_safe_harbour_scan(&mut applicator).unwrap();

        let BatchOutput { duties, tracker } = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
    }

    #[test]
    fn scan_helper_applies_transitions_on_a_latched_registry() {
        let mut registry = test_populated_registry(1);
        registry.activate_safe_harbour(test_safe_harbour_address());
        let mut applicator = Applicator::new(&mut registry, None);

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

        let BatchOutput { tracker, .. } = applicator.finish();
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

#[cfg(test)]
mod stake_initialization_tests {
    //! Initialization through membership signals, persistence, and routed retry events.

    use std::{
        collections::BTreeSet,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use bitcoin::{
        Amount, OutPoint, TxOut,
        hashes::{Hash, sha256},
    };
    use btc_tracker::event::{BlockEvent, BlockStatus};
    use libp2p_identity::Keypair;
    use strata_bridge_db::{
        fdb::{cfg::Config, client::FdbClient},
        traits::BridgeDb,
        types::{FundingAssignment, StakeFundingReservation},
    };
    use strata_bridge_primitives::{
        covenant::StakeKey,
        operator_set_schedule::{OperatorSetSchedule, ScheduledOperator},
        operator_table::PublicOperatorTable,
    };
    use strata_bridge_sm::{
        operator_set::{
            MembershipCause, MembershipUpdate, OperatorSetEvent, OperatorSetSM, OperatorSetSignal,
        },
        stake::{
            duties::StakeDuty,
            events::{StakeDataReceivedEvent, StakeEvent},
            state::StakeState,
        },
    };
    use strata_bridge_test_utils::bitcoin::{
        generate_block_with_height, generate_spending_tx, generate_txid,
    };

    use crate::{
        applicator::{Applicator, BatchOutput},
        errors::{PipelineError, ProcessError},
        events_classifier::{offchain, onchain},
        events_mux::UnifiedEvent,
        events_router,
        persister::{PersistError, Persister},
        signals_router,
        sm_registry::{RegistryInsertError, SMRegistry},
        sm_types::{SMId, UnifiedDuty},
        testing::{
            DrtBuilder, make_confirmed_stake_sm, random_p2tr_desc, test_empty_registry,
            test_fdb_config, test_operator_table, test_slash,
        },
    };

    fn registry() -> SMRegistry {
        let table = test_operator_table(3, 0);
        let registrations = table
            .operator_idxs()
            .into_iter()
            .map(|index| {
                ScheduledOperator::new(
                    index,
                    table.idx_to_btc_key(&index).unwrap().x_only_public_key().0,
                    Keypair::generate_ed25519()
                        .public()
                        .try_into_ed25519()
                        .unwrap()
                        .to_bytes()
                        .to_vec()
                        .into(),
                    random_p2tr_desc(),
                    100,
                    None,
                )
                .unwrap()
            })
            .collect();
        let membership = OperatorSetSM::new(
            100,
            OperatorSetSchedule::new(registrations).unwrap(),
            vec![MembershipUpdate {
                activation_height: 102,
                additions: BTreeSet::new(),
                removals: BTreeSet::from([1]),
            }],
        )
        .unwrap();
        let mut registry = test_empty_registry();
        registry.insert_operator_set(membership).unwrap();
        registry
    }

    fn apply_signals(
        applicator: &mut Applicator<'_>,
        signals: Vec<OperatorSetSignal>,
    ) -> Result<(), PipelineError> {
        for signal in signals {
            let events = signals_router::route_signal(applicator.registry(), signal.into())?;
            applicator.apply_batch(events)?;
        }
        Ok(())
    }

    fn advance_membership(applicator: &mut Applicator<'_>, height: u64) {
        applicator
            .apply_batch([(
                SMId::OperatorSet,
                OperatorSetEvent::NewBlock {
                    block_height: height,
                    exits: vec![],
                }
                .into(),
            )])
            .unwrap();
    }

    fn prepare(registry: &mut SMRegistry) -> BatchOutput {
        let signals = registry
            .get_operator_set()
            .unwrap()
            .prepare_covenant(102)
            .unwrap()
            .signals;
        let mut applicator = Applicator::new(registry, Some(0));
        apply_signals(&mut applicator, signals).unwrap();
        applicator.finish()
    }

    fn publication_key(duties: &[UnifiedDuty]) -> StakeKey {
        assert_eq!(duties.len(), 1, "only the local owner publishes stake data");
        match &duties[0] {
            UnifiedDuty::Stake {
                stake_key,
                duty: StakeDuty::PublishStakeData { operator_idx },
            } => {
                assert_eq!(*operator_idx, 0);
                assert_eq!(stake_key.operator, *operator_idx);
                *stake_key
            }
            other => panic!("expected constructor duty, got {other:?}"),
        }
    }

    fn retry(registry: &mut SMRegistry) -> BatchOutput {
        let event = UnifiedEvent::RetryTick;
        let events = events_router::route(&event, registry)
            .into_iter()
            .map(
                |id| match offchain::classify_routed(&id, &event, registry) {
                    offchain::ClassificationOutcome::Classified(event) => (id, event),
                    other => panic!("retry must classify: {other:?}"),
                },
            )
            .collect::<Vec<_>>();
        let mut applicator = Applicator::new(registry, Some(0));
        applicator.apply_batch(events).unwrap();
        applicator.finish()
    }

    #[test]
    fn block_exits_precede_admin_and_initialize_only_the_final_membership() {
        let mut registry = registry();
        // No local StakeSM exists for either the known exit or the unknown registration.
        let mut block = BlockEvent {
            block: generate_block_with_height(101),
            status: BlockStatus::Buried,
        };
        let mut applicator = Applicator::new(&mut registry, Some(0));
        onchain::process_stake_pass(&mut applicator, &block).unwrap();
        assert!(applicator.finish().duties.is_empty());
        block.block = generate_block_with_height(102);
        block
            .block
            .txdata
            .extend([test_slash(99), test_slash(1), test_slash(1), test_slash(2)]);
        let exit_index = block.block.txdata.len() as u32 - 3;
        let mut applicator = Applicator::new(&mut registry, Some(0));
        onchain::process_stake_pass(&mut applicator, &block).unwrap();
        let batch = applicator.finish();
        let final_key = publication_key(&batch.duties);
        assert_eq!(registry.get_stake_ids(), vec![final_key]);
        let membership = registry.get_operator_set().unwrap();
        let history = membership.membership_history();
        assert_eq!(history.len(), 4, "initial, two unique exits, admin no-op");
        assert!(matches!(
            &history[1].cause,
            MembershipCause::Exit(exit) if exit.operator_idx == 1 && exit.tx_index == exit_index
        ));
        assert!(matches!(&history[2].cause, MembershipCause::Exit(exit) if exit.operator_idx == 2));
        assert!(matches!(
            &history[3].cause,
            MembershipCause::Admin {
                effective: false,
                ..
            }
        ));
        assert_eq!(membership.current_covenant().activation_height, 100);
        assert_eq!(
            &membership.membership_history().last().unwrap().members,
            &BTreeSet::from([0])
        );
        assert_eq!(
            batch.tracker.into_batches(),
            vec![BTreeSet::from([SMId::OperatorSet, SMId::Stake(final_key),])]
        );
        let before = membership.clone();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        onchain::process_stake_pass(&mut applicator, &block).unwrap();
        let replay = applicator.finish();
        assert!(replay.duties.is_empty());
        assert!(replay.tracker.into_batches().is_empty());
        assert_eq!(registry.get_operator_set(), Some(&before));
    }

    #[test]
    fn observer_tracks_exits_and_admin_without_creating_participant_stakes() {
        let mut registry = registry();
        for height in [101, 102] {
            let mut block = BlockEvent {
                block: generate_block_with_height(height),
                status: BlockStatus::Buried,
            };
            if height == 101 {
                block.block.txdata.push(test_slash(0));
            }
            let mut applicator = Applicator::new(&mut registry, Some(0));
            onchain::process_stake_pass(&mut applicator, &block).unwrap();
            assert!(applicator.finish().duties.is_empty());
        }
        assert_eq!(registry.num_stakes(), 0);
        let membership = registry.get_operator_set().unwrap();
        assert_eq!(
            &membership.membership_history().last().unwrap().members,
            &BTreeSet::from([2])
        );
        assert_eq!(membership.current_covenant().activation_height, 102);
    }

    #[tokio::test]
    async fn successor_membership_closes_admission_but_keeps_historical_work_running() {
        let source = registry();
        let mut registry = test_empty_registry();
        registry
            .insert_operator_set(source.get_operator_set().unwrap().clone())
            .unwrap();
        let table = test_operator_table(3, 0);
        let covenant = registry.get_operator_set().unwrap().current_covenant();
        for operator in table.operator_idxs() {
            registry
                .insert_stake(make_confirmed_stake_sm(
                    operator,
                    table.clone(),
                    generate_txid(),
                ))
                .unwrap();
        }
        let mut initial_block = BlockEvent {
            block: generate_block_with_height(100),
            status: BlockStatus::Buried,
        };
        initial_block
            .block
            .txdata
            .push(DrtBuilder::aligned(&table, &registry.cfg().deposit).build());
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (client, guard) = FdbClient::setup(Config {
            root_directory: format!("test-successor-admission-{suffix}"),
            ..test_fdb_config()
        })
        .await
        .unwrap();
        let db = Arc::new(client);
        let persister = Persister::new(db.clone());
        let batch = super::process_block(&mut registry, &table, covenant, &initial_block).unwrap();
        persister
            .persist_batches(batch.tracker, &registry)
            .await
            .unwrap();
        let duties = batch.duties;
        assert_eq!(duties.len(), 1);
        let mut request = DrtBuilder::aligned(&table, &registry.cfg().deposit).build();
        request.input[0].previous_output = OutPoint::new(generate_txid(), 0);
        let mut block = BlockEvent {
            block: generate_block_with_height(101),
            status: BlockStatus::Buried,
        };
        block.block.txdata.extend([request, test_slash(1)]);
        let batch = super::process_block(&mut registry, &table, covenant, &block).unwrap();
        persister
            .persist_batches(batch.tracker, &registry)
            .await
            .unwrap();
        let duties = batch.duties;
        assert_eq!(
            registry.num_deposits(),
            1,
            "old-covenant DRT must not enter after membership changes"
        );
        assert_ne!(
            registry.get_operator_set().unwrap().current_covenant(),
            covenant
        );
        assert_eq!(
            registry.num_stakes(),
            5,
            "three historical and two successor stakes"
        );
        publication_key(&duties);
        assert_eq!(
            registry
                .get_deposit(&0)
                .unwrap()
                .state()
                .last_processed_block_height(),
            Some(&101)
        );
        for (_, graph) in registry.graphs() {
            assert_eq!(graph.state().last_processed_block_height(), Some(&101));
        }
        drop(persister);
        drop(db);
        drop(guard);
    }

    #[test]
    fn params_bootstrap_schedules_boundaries_and_preserves_existing_stakes() {
        let source = registry();
        let registrations = OperatorSetSchedule::new(
            source
                .get_operator_set()
                .unwrap()
                .registrations()
                .iter()
                .map(|op| {
                    ScheduledOperator::new(
                        op.index(),
                        op.covenant_key(),
                        op.p2p_key().clone(),
                        op.payout_descriptor().clone(),
                        op.activation_height(),
                        (op.index() == 1).then_some(102),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let mut registry = test_empty_registry();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        applicator
            .initialize_operator_set(registrations.clone(), 100)
            .unwrap();
        let initial = applicator.finish();
        publication_key(&initial.duties);
        assert_eq!(registry.num_stakes(), 3);
        assert_eq!(
            registry.get_operator_set().unwrap().pending_updates(),
            &[MembershipUpdate {
                activation_height: 102,
                additions: BTreeSet::new(),
                removals: BTreeSet::from([1]),
            }]
        );
        let stakes = registry
            .stakes()
            .map(|(key, sm)| (*key, sm.clone()))
            .collect::<Vec<_>>();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        applicator
            .initialize_operator_set(registrations, 999)
            .unwrap();
        let replay = applicator.finish();
        assert!(replay.duties.is_empty());
        assert!(replay.tracker.into_batches().is_empty());
        assert_eq!(
            registry
                .stakes()
                .map(|(key, sm)| (*key, sm.clone()))
                .collect::<Vec<_>>(),
            stakes
        );
    }

    #[test]
    fn membership_transition_initializes_exact_members_at_processing_height() {
        let mut registry = registry();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        advance_membership(&mut applicator, 101);
        advance_membership(&mut applicator, 102);
        let BatchOutput { duties, tracker } = applicator.finish();
        let key = publication_key(&duties);
        assert_eq!(
            registry.get_stake_ids(),
            vec![key, StakeKey { operator: 2, ..key }]
        );
        assert_eq!(
            tracker.into_batches(),
            vec![BTreeSet::from([
                SMId::OperatorSet,
                SMId::Stake(key),
                SMId::Stake(StakeKey { operator: 2, ..key }),
            ])]
        );
        for (_, sm) in registry.stakes() {
            assert_eq!(
                sm.state(),
                &StakeState::Created {
                    last_block_height: 102
                }
            );
        }

        // Constructor advancement already accounts for 102; the ordinary block path must not
        // deliver another current-height event or persist it again. The next block advances once.
        for (height, advances) in [(102, false), (103, true), (103, false)] {
            let mut applicator = Applicator::new(&mut registry, Some(0));
            onchain::process_stake_pass(
                &mut applicator,
                &BlockEvent {
                    block: generate_block_with_height(height),
                    status: BlockStatus::Buried,
                },
            )
            .unwrap();
            let BatchOutput { duties, tracker } = applicator.finish();
            assert!(duties.is_empty());
            let batches = tracker.into_batches();
            assert_eq!(
                batches.is_empty(),
                !advances,
                "advance each stake only once at {height}"
            );
            for (_, sm) in registry.stakes() {
                assert_eq!(sm.state().last_processed_block_height(), Some(height));
            }
        }
    }

    #[test]
    fn preparation_and_duplicate_signals_preserve_staking_progress() {
        let mut registry = registry();
        let membership = registry.get_operator_set().unwrap().clone();
        let signals = membership.prepare_covenant(102).unwrap().signals;
        let BatchOutput { duties, tracker } = prepare(&mut registry);
        let key = publication_key(&duties);
        assert_eq!(key.covenant.activation_height, 102);
        assert_eq!(
            registry
                .get_stake(&key)
                .unwrap()
                .state()
                .last_processed_block_height(),
            Some(100)
        );
        assert_eq!(registry.get_operator_set(), Some(&membership));
        assert!(tracker.into_batches()[0].contains(&SMId::OperatorSet));

        let mut applicator = Applicator::new(&mut registry, Some(0));
        applicator
            .apply_batch([(
                SMId::Stake(key),
                StakeEvent::StakeDataReceived(StakeDataReceivedEvent {
                    stake_funds: OutPoint::null(),
                    unstaking_image: sha256::Hash::hash(&[7; 32]),
                    unstaking_output_desc: random_p2tr_desc(),
                })
                .into(),
            )])
            .unwrap();
        applicator.finish();
        let before = registry.get_stake(&key).unwrap().clone();
        assert!(matches!(
            before.state(),
            StakeState::StakeGraphGenerated { .. }
        ));

        let mut applicator = Applicator::new(&mut registry, Some(0));
        apply_signals(&mut applicator, signals.clone()).unwrap();
        apply_signals(&mut applicator, signals).unwrap();
        let BatchOutput { duties, tracker } = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
        assert_eq!(registry.get_stake(&key), Some(&before));

        let mut applicator = Applicator::new(&mut registry, Some(0));
        advance_membership(&mut applicator, 101);
        advance_membership(&mut applicator, 102);
        advance_membership(&mut applicator, 102);
        let BatchOutput { duties, .. } = applicator.finish();
        assert!(
            duties.is_empty(),
            "activation must reuse the prepared instances"
        );
        assert_eq!(registry.num_stakes(), 2);
        assert_eq!(registry.get_stake(&key), Some(&before));
        let BatchOutput { duties, .. } = retry(&mut registry);
        assert!(
            duties.is_empty(),
            "publication recovery stops after stake data arrives"
        );
    }

    #[test]
    fn conflicting_recreation_identifies_exact_stake_and_preserves_progress() {
        let mut registry = registry();
        let BatchOutput { duties, .. } = prepare(&mut registry);
        let key = publication_key(&duties);
        let before = registry.get_stake(&key).unwrap().clone();
        let table = before.context().operator_table();
        // Same aggregate and activation height, but conflicting immutable P2P membership.
        let conflicting = PublicOperatorTable::from_entries(
            table
                .operator_idxs()
                .into_iter()
                .map(|idx| {
                    (
                        idx,
                        vec![idx as u8 + 10; 32].into(),
                        table.idx_to_btc_key(&idx).unwrap(),
                    )
                })
                .collect(),
        )
        .unwrap();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        let error = apply_signals(
            &mut applicator,
            vec![OperatorSetSignal::InitializeStake {
                stake_key: key,
                operator_table: conflicting,
            }],
        )
        .unwrap_err();
        assert!(
            matches!(error, PipelineError::Process(ProcessError::RegistryInsert(RegistryInsertError::CovenantMembershipMismatch(actual))) if actual == key)
        );
        assert!(error.to_string().contains(&key.to_string()));
        let BatchOutput { duties, tracker } = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
        assert_eq!(registry.get_stake(&key), Some(&before));
    }

    #[test]
    fn observers_and_removed_or_unrelated_operators_emit_no_constructor_duties() {
        for local_operator in [None, Some(1), Some(99)] {
            let mut registry = registry();
            let mut applicator = Applicator::new(&mut registry, local_operator);
            advance_membership(&mut applicator, 101);
            advance_membership(&mut applicator, 102);
            let BatchOutput { duties, tracker } = applicator.finish();
            assert!(duties.is_empty());
            assert_eq!(registry.num_stakes(), 0);
            assert_eq!(
                tracker.into_batches(),
                vec![BTreeSet::from([SMId::OperatorSet])]
            );
            assert_eq!(
                registry
                    .get_operator_set()
                    .unwrap()
                    .current_operator_table()
                    .unwrap()
                    .operator_idxs(),
                BTreeSet::from([0, 2])
            );
        }
    }

    #[tokio::test]
    async fn initialization_failure_and_post_commit_recovery_preserve_funding_identity() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (client, guard) = FdbClient::setup(Config {
            root_directory: format!("test-stake-initialization-{suffix}"),
            ..test_fdb_config()
        })
        .await
        .unwrap();
        let db = Arc::new(client);
        let persister = Persister::new(db.clone());
        let mut registry = registry();
        let cfg = registry.cfg().clone();
        persister
            .persist_batch(BTreeSet::from([SMId::OperatorSet]), &registry)
            .await
            .unwrap();
        let original_membership = registry.get_operator_set().unwrap().clone();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        advance_membership(&mut applicator, 101);
        advance_membership(&mut applicator, 102);
        let mut batch = applicator.finish();
        let key = publication_key(&batch.duties);
        // A missing causal dependency fails real batch construction before committing any stake.
        batch.tracker.link(SMId::OperatorSet, SMId::Deposit(999));
        let result = persister.persist_batches(batch.tracker, &registry).await;
        assert!(matches!(
            result,
            Err(PersistError::MissingStateMachine(SMId::Deposit(999)))
        ));
        assert!(db.get_persisted_state().await.unwrap().stakes.is_empty());
        assert_eq!(
            db.get_persisted_state().await.unwrap().operator_set,
            Some(original_membership)
        );

        // Recover from the last durable state, as the pipeline does after its fatal error.
        registry = persister.recover_registry(cfg.clone()).await.unwrap();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        advance_membership(&mut applicator, 101);
        advance_membership(&mut applicator, 102);
        let batch = applicator.finish();
        assert_eq!(publication_key(&batch.duties), key);
        // Simulate losing the process after commit but before constructor dispatch.
        persister
            .persist_batches(batch.tracker, &registry)
            .await
            .unwrap();
        drop(batch.duties);
        let mut recovered = persister.recover_registry(cfg.clone()).await.unwrap();
        assert_eq!(recovered.get_operator_set(), registry.get_operator_set());
        assert_eq!(recovered.get_stake_ids(), registry.get_stake_ids());
        let mut applicator = Applicator::new(&mut recovered, Some(0));
        advance_membership(&mut applicator, 102);
        let signals = applicator
            .registry()
            .get_operator_set()
            .unwrap()
            .initialization_signals()
            .unwrap();
        apply_signals(&mut applicator, signals).unwrap();
        let BatchOutput { duties, tracker } = applicator.finish();
        assert!(
            duties.is_empty(),
            "duplicate initialization does not fund again"
        );
        assert!(tracker.into_batches().is_empty());
        let BatchOutput { duties, tracker } = retry(&mut recovered);
        assert_eq!(publication_key(&duties), key);
        assert!(
            tracker.into_batches().is_empty(),
            "recover the duty without resetting progress"
        );

        // The executor's covenant-qualified reservation path keeps the original funding on retry,
        // including a crash after reservation but before stake data is delivered back to the SM.
        let mut tx = generate_spending_tx(OutPoint::null(), &[]);
        tx.output.push(TxOut::NULL);
        let reservation = StakeFundingReservation {
            unsigned_tx: tx,
            prevouts: vec![TxOut::NULL],
            stake_output_vout: 0,
        };
        assert_eq!(
            db.get_or_set_stake_funding_reservation(key, reservation.clone())
                .await
                .unwrap(),
            FundingAssignment::Created(reservation.clone())
        );
        let mut recovered = persister.recover_registry(cfg).await.unwrap();
        let batch = retry(&mut recovered);
        persister
            .persist_batches(batch.tracker, &recovered)
            .await
            .unwrap();
        let resumed_key = publication_key(&batch.duties);
        assert_eq!(resumed_key, key);
        let mut replacement = reservation.clone();
        replacement.unsigned_tx.output[0].value = Amount::from_sat(42);
        assert_eq!(
            db.get_or_set_stake_funding_reservation(resumed_key, replacement)
                .await
                .unwrap(),
            FundingAssignment::Existing(reservation.clone())
        );
        assert_eq!(
            db.get_stake_funding_reservation(key).await.unwrap(),
            Some(reservation)
        );
        assert_eq!(recovered.num_stakes(), 2);
        drop(persister);
        drop(db);
        drop(guard);
    }
}

#[cfg(test)]
mod block_persistence_tests {
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use bitcoin::OutPoint;
    use btc_tracker::event::BlockStatus;
    use strata_bridge_db::fdb::{cfg::Config, client::FdbClient};
    use strata_bridge_sm::stake::state::StakeState;
    use strata_bridge_test_utils::{
        bitcoin::{
            generate_block_with_height, generate_signature, generate_spending_tx, generate_txid,
        },
        musig2::generate_agg_nonce,
    };
    use strata_bridge_tx_graph::musig_functor::StakeFunctor;

    use super::*;
    use crate::testing::{
        DrtBuilder, INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_POV_IDX, make_confirmed_stake_sm,
        test_fdb_config, test_operator_table, test_populated_registry,
    };

    #[tokio::test]
    async fn durable_block_replay_cannot_admit_an_older_unready_request() {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let covenant = CovenantId::from_operator_table(&table, INITIAL_BLOCK_HEIGHT).unwrap();
        let mut registry = test_populated_registry(0);
        let stake_tx = generate_spending_tx(OutPoint::new(generate_txid(), 0), &[]);
        for operator in table.operator_idxs() {
            let mut stake = make_confirmed_stake_sm(operator, table.clone(), generate_txid());
            if operator == TEST_POV_IDX {
                let StakeState::Confirmed {
                    last_block_height,
                    stake_data,
                    mut summary,
                    ..
                } = stake.state
                else {
                    unreachable!()
                };
                summary.stake = stake_tx.compute_txid();
                let fields = StakeFunctor {
                    unstaking_intent: [()],
                    unstaking: [(), ()],
                };
                stake.state = StakeState::UnstakingSigned {
                    last_block_height,
                    stake_data,
                    summary,
                    agg_nonces: fields.map(|_| generate_agg_nonce()).boxed(),
                    signatures: fields.map(|_| generate_signature()).boxed(),
                };
            }
            registry.insert_stake(stake).unwrap();
        }
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (client, guard) = FdbClient::setup(Config {
            root_directory: format!("test-block-gate-{suffix}"),
            ..test_fdb_config()
        })
        .await
        .unwrap();
        let db = Arc::new(client);
        let persister = Persister::new(db.clone());
        let mut old = BlockEvent {
            block: generate_block_with_height(INITIAL_BLOCK_HEIGHT + 1),
            status: BlockStatus::Buried,
        };
        old.block
            .txdata
            .push(DrtBuilder::aligned(&table, &registry.cfg().deposit).build());
        let batch = process_block(&mut registry, &table, covenant, &old).unwrap();
        assert!(batch.duties.is_empty());
        persister
            .persist_batches(batch.tracker, &registry)
            .await
            .unwrap();
        assert_eq!(registry.num_deposits(), 0);
        let mut next = BlockEvent {
            block: generate_block_with_height(INITIAL_BLOCK_HEIGHT + 2),
            status: BlockStatus::Buried,
        };
        next.block.txdata.push(stake_tx);
        next.block
            .txdata
            .push(DrtBuilder::aligned(&table, &registry.cfg().deposit).build());
        let batch = process_block(&mut registry, &table, covenant, &next).unwrap();
        assert_eq!(batch.duties.len(), 1);
        persister
            .persist_batches(batch.tracker, &registry)
            .await
            .unwrap();
        let mut restored = persister
            .recover_registry(registry.cfg().clone())
            .await
            .unwrap();
        let deposit = restored.get_deposit(&0).unwrap().clone();
        let batch = process_block(&mut restored, &table, covenant, &old).unwrap();
        assert!(batch.duties.is_empty());
        persister
            .persist_batches(batch.tracker, &restored)
            .await
            .unwrap();
        let batch = process_block(&mut restored, &table, covenant, &next).unwrap();
        assert!(batch.duties.is_empty());
        persister
            .persist_batches(batch.tracker, &restored)
            .await
            .unwrap();
        assert_eq!(restored.num_deposits(), 1);
        assert_eq!(restored.get_deposit(&0), Some(&deposit));
        assert_eq!(
            restored.latest_gate_height(),
            Some(INITIAL_BLOCK_HEIGHT + 2)
        );
        drop(persister);
        drop(db);
        drop(guard);
    }
}
