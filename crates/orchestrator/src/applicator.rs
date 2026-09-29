//! The fixed-point batch processor for state machine events.
//!
//! The [`Applicator`] owns the STF execution, signal cascade, duty accumulation, and persistence
//! tracking logic. It provides a single entry point ([`apply_batch`](Applicator::apply_batch)) that
//! processes a set of seed events to a fixed point — all signals are drained and no intermediate
//! state is externally visible until the batch settles.
//!
//! Both on-chain (per-transaction) and off-chain (per-event) paths use the same `Applicator`,
//! ensuring uniform batch semantics across the pipeline.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use strata_bridge_primitives::{
    covenant::StakeKey,
    operator_set_schedule::OperatorSetSchedule,
    operator_table::PublicOperatorTable,
    types::{BitcoinBlockHeight, DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_sm::{
    deposit::machine::DepositSM,
    graph::machine::GraphSM,
    operator_set::{MembershipUpdate, OperatorSetEvent, OperatorSetSM},
    stake::{context::StakeSMCtx, machine::StakeSM},
};
use tracing::{debug, info, warn};

use crate::{
    errors::{PipelineError, ProcessError},
    persister::PersistenceTracker,
    signals_router,
    sm_registry::{IgnoredEventReason, ProcessOutcome, RegistryInsertError, SMRegistry},
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

/// Accumulated duties and the state-machine dependencies that must be persisted before dispatch.
#[derive(Debug)]
pub struct BatchOutput {
    /// Duties emitted while applying events and initializing state machines.
    pub duties: Vec<UnifiedDuty>,
    /// Causal groups containing the state needed to recover these duties.
    pub tracker: PersistenceTracker,
}

/// A fixed-point batch processor that drives state machine transitions and signal cascades.
///
/// Created once per top-level event (off-chain) or once per block (on-chain), the `Applicator`
/// accumulates duties and tracks persistence across one or more [`apply_batch`](Self::apply_batch)
/// calls, then yields its results via [`finish`](Self::finish).
#[expect(missing_debug_implementations)]
pub struct Applicator<'a> {
    registry: &'a mut SMRegistry,
    local_operator: Option<OperatorIdx>,
    tracker: PersistenceTracker,
    duties: Vec<UnifiedDuty>,
    signal_queue: VecDeque<(SMId, SMEvent)>,
}

impl<'a> Applicator<'a> {
    /// Creates an applicator with this node's optional signing registration.
    ///
    /// A node absent from a requested covenant observes public membership without creating
    /// participant StakeSMs. Historical instances remain in the registry.
    pub fn new(registry: &'a mut SMRegistry, local_operator: Option<OperatorIdx>) -> Self {
        Self {
            registry,
            local_operator,
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
    /// 2. Drains the signal queue until no more signals remain.
    /// 3. Accumulates all duties produced.
    /// 4. Updates the persistence tracker for every touched state machine.
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

    /// Inserts a new deposit state machine into the registry and records it for persistence.
    ///
    /// Newly constructed SMs start in their initial state and typically do not classify the
    /// current transaction into an event, so they would otherwise never reach any `apply_*` calls
    /// and never be marked as touched. Routing insertions through the
    /// applicator makes insertion and persistence-tracking atomic, so callers cannot accidentally
    /// leave a new SM unrecorded and drop it on crash before its first transition.
    pub fn insert_deposit(
        &mut self,
        deposit_idx: DepositIdx,
        sm: DepositSM,
    ) -> Result<(), RegistryInsertError> {
        self.registry.insert_deposit(deposit_idx, sm)?;
        self.tracker.record(SMId::Deposit(deposit_idx));
        Ok(())
    }

    /// Inserts a graph state machine and groups its persistence with its parent deposit.
    ///
    /// DRT replay skips deposits already in the registry, so their graphs must be committed in
    /// the same batch to prevent recovery from leaving a partially registered deposit.
    ///
    /// See [`insert_deposit`](Self::insert_deposit) for why the applicator owns this insertion.
    pub fn insert_graph(
        &mut self,
        graph_idx: GraphIdx,
        sm: GraphSM,
    ) -> Result<(), RegistryInsertError> {
        self.registry.insert_graph(graph_idx, sm)?;
        self.tracker
            .link(SMId::Deposit(graph_idx.deposit), SMId::Graph(graph_idx));
        Ok(())
    }

    /// Applies a registration schedule and initializes missing stakes for the current covenant.
    ///
    /// Uses `block_height` only when membership has not yet been initialized.
    /// Existing membership history and stake progress are preserved.
    pub fn initialize_operator_set(
        &mut self,
        registrations: OperatorSetSchedule,
        block_height: BitcoinBlockHeight,
    ) -> Result<(), PipelineError> {
        let height = self
            .registry
            .get_operator_set()
            .map_or(block_height, OperatorSetSM::last_block_height);

        // Params encode one additions-before-removals operation at each interval boundary.
        let mut updates = BTreeMap::new();
        for registration in &registrations {
            let activation_height = registration.activation_height();
            if activation_height > height {
                let update = updates
                    .entry(activation_height)
                    .or_insert(MembershipUpdate {
                        activation_height,
                        additions: BTreeSet::new(),
                        removals: BTreeSet::new(),
                    });
                update.additions.insert(registration.index());
            }

            if let Some(deactivation_height) = registration.deactivation_height()
                && deactivation_height > height
            {
                let update = updates
                    .entry(deactivation_height)
                    .or_insert(MembershipUpdate {
                        activation_height: deactivation_height,
                        additions: BTreeSet::new(),
                        removals: BTreeSet::new(),
                    });
                update.removals.insert(registration.index());
            }
        }

        let pending_updates = updates.into_values().collect();
        if self.registry.get_operator_set().is_some() {
            self.apply_batch([(
                SMId::OperatorSet,
                OperatorSetEvent::UpdateOperatorTable {
                    registrations,
                    pending_updates,
                }
                .into(),
            )])?;
        } else {
            let membership = OperatorSetSM::new(height, registrations, pending_updates)
                .map_err(ProcessError::from)?;
            self.registry
                .insert_operator_set(membership)
                .map_err(ProcessError::from)?;
            self.tracker.record(SMId::OperatorSet);
        }

        let signals = self
            .registry
            .get_operator_set()
            .expect("membership installed")
            .initialization_signals()
            .map_err(ProcessError::from)?;
        for signal in signals {
            let events = signals_router::route_signal(self.registry, signal.into())?;
            self.apply_batch(events)?;
        }

        Ok(())
    }

    /// Initializes a participant stake, preserving matching immutable context and all progress.
    ///
    /// The constructor clock is the current processing position, not the activation boundary.
    /// Records newly created stakes for persistence and accumulates any constructor duty.
    /// Returns `true` if a stake was created, or `false` if it already existed or this node
    /// is not a participant in the requested covenant.
    pub fn initialize_stake(
        &mut self,
        stake_key: StakeKey,
        operator_table: PublicOperatorTable,
        block_height: BitcoinBlockHeight,
    ) -> Result<bool, ProcessError> {
        if let Some(existing) = self.registry.get_stake(&stake_key) {
            if !existing
                .context()
                .operator_table()
                .has_same_membership(&operator_table)
            {
                return Err(RegistryInsertError::CovenantMembershipMismatch(stake_key).into());
            }
            return Ok(false);
        }

        let Some(table) = self
            .local_operator
            .and_then(|idx| operator_table.with_pov(idx))
        else {
            warn!(
                "skipping creation of stake {stake_key:?} because local operator is not in the requested covenant"
            );
            return Ok(false);
        };

        info!(
            ?stake_key,
            ?table,
            "initializing stake state machine for local operator"
        );
        let context = StakeSMCtx::new(
            stake_key.operator,
            table,
            stake_key.covenant.activation_height,
        );
        let (sm, initial_duty) = StakeSM::new(context, block_height);

        self.registry.insert_stake(sm)?;
        self.tracker.record(SMId::Stake(stake_key));

        if let Some(duty) = initial_duty {
            self.duties.push(UnifiedDuty::Stake { stake_key, duty });
        }

        Ok(true)
    }

    /// Consumes the applicator and returns the accumulated duties and persistence tracker.
    pub fn finish(self) -> BatchOutput {
        BatchOutput {
            duties: self.duties,
            tracker: self.tracker,
        }
    }

    /// Processes a single event through the registry's STF.
    ///
    /// On success, accumulates duties and enqueues any signal-derived events. Ignored outcomes are
    /// non-fatal: duplicates are debug-logged and rejections are warning-logged by the applicator.
    /// Fatal errors are propagated.
    ///
    /// Persistence tracking follows the state machine's own report: a transition that leaves state
    /// unchanged (e.g. a nag or retry tick) still has its duties accumulated and its signals
    /// enqueued, but the source SM is not otherwise recorded. Stake initialization groups
    /// created stakes with the membership transition that requested them.
    fn apply_one(&mut self, sm_id: SMId, sm_event: SMEvent) -> Result<(), PipelineError> {
        if let (
            SMId::Stake(stake_key),
            SMEvent::InitializeStake {
                operator_table,
                block_height,
            },
        ) = (&sm_id, &sm_event)
        {
            let created =
                self.initialize_stake(*stake_key, operator_table.as_ref().clone(), *block_height)?;
            if created {
                // Persist the membership transition and the stakes it creates atomically.
                self.tracker.link(SMId::OperatorSet, sm_id);
            }
            return Ok(());
        }

        match self.registry.process_event(&sm_id, sm_event) {
            Ok(ProcessOutcome::Applied(output)) => {
                let mutated = output.did_mutate();
                if mutated {
                    self.tracker.record(sm_id);
                }

                self.duties.extend(output.duties);

                for signal in output.signals {
                    for (target_id, target_event) in
                        signals_router::route_signal(self.registry, signal)?
                    {
                        // Initialization links its source when the queued event creates a stake.
                        // Linking here could add a nonexistent target to persistence if this node
                        // is not a participant and initialization is skipped.
                        let is_target_stake_init =
                            matches!(&target_event, SMEvent::InitializeStake { .. });

                        if mutated && !is_target_stake_init {
                            self.tracker.link(sm_id, target_id);
                        }

                        self.signal_queue.push_back((target_id, target_event));
                    }
                }

                Ok(())
            }

            Ok(ProcessOutcome::Ignored { id, event, reason }) => {
                match reason {
                    IgnoredEventReason::Duplicate => {
                        debug!(?id, %event, "duplicate state-machine event ignored");
                    }
                    IgnoredEventReason::Rejected(reason) => {
                        warn!(?id, %event, %reason, "state-machine event rejected");
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

    use bitcoin::{
        Amount, OutPoint,
        hashes::{Hash, sha256},
    };
    use strata_bridge_primitives::{covenant::CovenantId, types::GraphIdx};
    use strata_bridge_sm::{
        deposit::{
            events::{DepositEvent, NewBlockEvent as DepositNewBlock, UserTakeBackEvent},
            state::DepositState,
        },
        graph::{
            context::GraphSMCtx,
            events::{GraphEvent, NewBlockEvent as GraphNewBlock},
            state::{AbortReason, GraphState},
        },
        stake::{
            duties::StakeDuty,
            events::{NewBlockEvent, StakeDataReceivedEvent, StakeEvent},
            state::StakeState,
        },
    };
    use strata_bridge_test_utils::bitcoin::generate_spending_tx;
    use strata_bridge_tx_graph::transactions::prelude::DepositData;

    use super::*;
    use crate::testing::{
        INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_POV_IDX, random_p2tr_desc,
        test_deposit_sm_cfg, test_empty_registry, test_operator_table, test_populated_registry,
    };

    // ===== apply_batch basic tests =====

    #[test]
    fn empty_batch_yields_no_duties_and_no_touched_sms() {
        let mut registry = test_populated_registry(1);
        let mut applicator = Applicator::new(&mut registry, None);

        applicator.apply_batch(vec![]).unwrap();

        let BatchOutput { duties, tracker } = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
    }

    #[test]
    fn insert_deposit_marks_sm_for_persistence_without_any_event() {
        // Freshly inserted SMs do not classify the current transaction (their initial state
        // returns `None` from the classifier), so they never reach `apply_one()` and would be
        // omitted from the persistence batch unless routed through the applicator. This guards
        // against a durability gap where a new DSM could be lost on crash before its first
        // transition.
        let mut registry = test_empty_registry();
        let mut applicator = Applicator::new(&mut registry, None);

        let dsm = test_deposit_sm(0);
        applicator
            .insert_deposit(0, dsm)
            .expect("insertion should succeed");
        applicator.apply_batch(vec![]).unwrap();

        let BatchOutput { tracker, .. } = applicator.finish();
        let batches = tracker.into_batches();
        let flat: BTreeSet<SMId> = batches.into_iter().flatten().collect();
        assert!(
            flat.contains(&SMId::Deposit(0)),
            "insert_deposit must add the SM to the persistence batch even with no STF events"
        );
    }

    #[test]
    fn insert_graph_persists_with_parent_deposit_without_any_event() {
        let mut registry = test_empty_registry();
        let mut applicator = Applicator::new(&mut registry, None);
        applicator.insert_deposit(0, test_deposit_sm(0)).unwrap();

        let graph_idx = GraphIdx {
            deposit: 0,
            operator: 0,
        };
        let gsm = test_graph_sm(graph_idx);
        applicator
            .insert_graph(graph_idx, gsm)
            .expect("insertion should succeed");
        applicator.apply_batch(vec![]).unwrap();

        let BatchOutput { tracker, .. } = applicator.finish();
        let batches = tracker.into_batches();
        assert_eq!(
            batches,
            vec![BTreeSet::from([SMId::Deposit(0), SMId::Graph(graph_idx)])]
        );
    }

    #[test]
    fn insert_deposit_duplicate_does_not_record_duplicate() {
        // Propagating the insertion error without recording avoids tracking an SM that was not
        // actually inserted; the original entry remains the source of truth.
        let mut registry = test_empty_registry();
        let mut applicator = Applicator::new(&mut registry, None);

        applicator.insert_deposit(0, test_deposit_sm(0)).unwrap();

        let err = applicator
            .insert_deposit(0, test_deposit_sm(0))
            .unwrap_err();
        assert!(matches!(
            err,
            crate::sm_registry::RegistryInsertError::DepositAlreadyExists(0)
        ));

        let BatchOutput { tracker, .. } = applicator.finish();
        let flat: Vec<SMId> = tracker.into_batches().into_iter().flatten().collect();
        assert_eq!(flat, vec![SMId::Deposit(0)]);
    }

    fn test_deposit_sm(deposit_idx: DepositIdx) -> DepositSM {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let cfg = test_deposit_sm_cfg();
        let depositor_pubkey = operator_table.pov_btc_key().x_only_public_key().0;
        let data = DepositData {
            deposit_idx,
            deposit_request_outpoint: OutPoint::default(),
            magic_bytes: cfg.magic_bytes(),
        };
        let drt_amount = cfg.deposit_amount() + Amount::from_sat(10_000);
        DepositSM::new(
            cfg,
            operator_table,
            data,
            depositor_pubkey,
            drt_amount,
            INITIAL_BLOCK_HEIGHT,
        )
    }

    fn test_graph_sm(graph_idx: GraphIdx) -> GraphSM {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let gsm_ctx = GraphSMCtx {
            covenant: CovenantId::from_operator_table(&operator_table, 100).unwrap(),
            graph_idx,
            deposit_outpoint: OutPoint::default(),
            stake_outpoint: OutPoint::default(),
            unstaking_image: <sha256::Hash as bitcoin::hashes::Hash>::all_zeros(),
            operator_table,
        };
        let (gsm, _duty) = GraphSM::new(gsm_ctx, INITIAL_BLOCK_HEIGHT);
        gsm
    }

    #[test]
    fn applied_event_marks_sm_as_touched() {
        let mut registry = test_populated_registry(1);
        let height = INITIAL_BLOCK_HEIGHT + 1;

        let mut applicator = Applicator::new(&mut registry, None);

        let seed_events = vec![(
            SMId::Deposit(0),
            SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
                block_height: height,
            }))),
        )];

        applicator.apply_batch(seed_events).unwrap();

        let BatchOutput { tracker, .. } = applicator.finish();
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

        let mut applicator = Applicator::new(&mut registry, None);

        let seed_events = vec![(
            SMId::Graph(graph_idx),
            SMEvent::Graph(Box::new(GraphEvent::NewBlock(GraphNewBlock {
                block_height: height,
            }))),
        )];

        applicator.apply_batch(seed_events).unwrap();

        let BatchOutput { tracker, .. } = applicator.finish();
        let batches = tracker.into_batches();
        assert!(!batches.is_empty());
    }

    #[test]
    fn deposit_request_takeback_signal_aborts_all_deposit_graphs() {
        let mut registry = test_populated_registry(2);
        let deposit_idx = 0;
        let takeback_tx =
            generate_spending_tx(OutPoint::default(), &[vec![0u8; 64], vec![1u8; 32]]);
        let takeback_txid = takeback_tx.compute_txid();

        let mut applicator = Applicator::new(&mut registry, None);
        applicator
            .apply_batch(vec![(
                SMId::Deposit(deposit_idx),
                SMEvent::Deposit(Box::new(DepositEvent::UserTakeBack(UserTakeBackEvent {
                    tx: takeback_tx,
                }))),
            )])
            .unwrap();

        assert_eq!(
            applicator
                .registry()
                .get_deposit(&deposit_idx)
                .expect("deposit SM must exist")
                .state(),
            &DepositState::Aborted,
            "DRT takeback must abort deposit {deposit_idx}"
        );

        for operator in 0..N_TEST_OPERATORS as u32 {
            let graph_idx = GraphIdx {
                deposit: deposit_idx,
                operator,
            };
            let graph_state = applicator
                .registry()
                .get_graph(&graph_idx)
                .expect("graph SM must exist")
                .state();

            assert!(
                matches!(
                    graph_state,
                    GraphState::Aborted {
                        claim_txid: None,
                        reason: AbortReason::DepositRequestTakenBack { spending_txid },
                    } if *spending_txid == takeback_txid
                ),
                "expected graph {graph_idx:?} to abort from DRT takeback, got {graph_state:?}"
            );
        }

        for operator in 0..N_TEST_OPERATORS as u32 {
            let graph_idx = GraphIdx {
                deposit: 1,
                operator,
            };
            let graph_state = applicator
                .registry()
                .get_graph(&graph_idx)
                .expect("other deposit graph SM must exist")
                .state();
            assert!(
                matches!(graph_state, GraphState::Created { .. }),
                "DRT takeback for deposit {deposit_idx} must not mutate graph {graph_idx:?}"
            );
        }

        let BatchOutput { tracker, .. } = applicator.finish();
        let batches = tracker.into_batches();
        assert_eq!(
            batches.len(),
            1,
            "DRT takeback cascade must be persisted as one atomic batch"
        );

        let batch = &batches[0];
        assert!(
            batch.contains(&SMId::Deposit(deposit_idx)),
            "persistence batch must include aborted deposit {deposit_idx}"
        );
        for operator in 0..N_TEST_OPERATORS as u32 {
            let graph_idx = GraphIdx {
                deposit: deposit_idx,
                operator,
            };
            assert!(
                batch.contains(&SMId::Graph(graph_idx)),
                "persistence batch must include aborted graph {graph_idx:?}"
            );
        }
        for operator in 0..N_TEST_OPERATORS as u32 {
            let graph_idx = GraphIdx {
                deposit: 1,
                operator,
            };
            assert!(
                !batch.contains(&SMId::Graph(graph_idx)),
                "persistence batch must not include unaffected graph {graph_idx:?}"
            );
        }
    }

    #[test]
    fn successive_batches_accumulate_touched_sms() {
        let mut registry = test_populated_registry(2);
        let height = INITIAL_BLOCK_HEIGHT + 1;

        let mut applicator = Applicator::new(&mut registry, None);

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

        let BatchOutput { tracker, .. } = applicator.finish();
        let all_ids: BTreeSet<_> = tracker.into_batches().into_iter().flatten().collect();
        assert!(all_ids.contains(&SMId::Deposit(0)));
        assert!(all_ids.contains(&SMId::Deposit(1)));
    }

    // ===== Error handling tests =====

    #[test]
    fn unknown_sm_id_is_fatal() {
        let mut registry = test_empty_registry();
        let mut applicator = Applicator::new(&mut registry, None);

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
        let mut applicator = Applicator::new(&mut registry, None);

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

        let BatchOutput { tracker, .. } = applicator.finish();
        assert!(!tracker.into_batches().is_empty());
    }

    // ===== Registry access between batches =====

    #[test]
    fn registry_reflects_settled_state_between_batches() {
        let mut registry = test_populated_registry(1);
        let mut applicator = Applicator::new(&mut registry, None);

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

    #[test]
    fn initialization_tracks_requested_stakes_and_only_emits_owner_duty() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(3, 0);
        let covenant = CovenantId::from_operator_table(&table, 200).unwrap();
        let mut applicator = Applicator::new(&mut registry, Some(0));
        let keys: Vec<_> = table
            .operator_idxs()
            .into_iter()
            .map(|operator| StakeKey { covenant, operator })
            .collect();
        for key in &keys {
            assert!(
                applicator
                    .initialize_stake(*key, table.clone().into_public(), 100)
                    .unwrap()
            );
        }
        let BatchOutput { duties, tracker } = applicator.finish();
        assert_eq!(registry.get_stake_ids(), keys);
        for (_, sm) in registry.stakes() {
            assert_eq!(
                sm.state(),
                &StakeState::Created {
                    last_block_height: 100
                }
            );
        }
        assert_eq!(duties.len(), 1);
        assert!(
            matches!(&duties[0], UnifiedDuty::Stake { stake_key, duty: StakeDuty::PublishStakeData { operator_idx: 0 } } if *stake_key == keys[0])
        );
        assert_eq!(
            tracker
                .into_batches()
                .into_iter()
                .flatten()
                .collect::<BTreeSet<_>>(),
            keys.into_iter().map(SMId::Stake).collect()
        );
    }

    #[test]
    fn matching_initialization_preserves_progress_and_processing_cursor() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(3, 0);
        let key = StakeKey {
            covenant: CovenantId::from_operator_table(&table, 200).unwrap(),
            operator: 0,
        };
        let mut applicator = Applicator::new(&mut registry, Some(0));
        assert!(
            applicator
                .initialize_stake(key, table.clone().into_public(), 100)
                .unwrap()
        );
        applicator
            .apply_batch([
                (
                    SMId::Stake(key),
                    StakeEvent::NewBlock(NewBlockEvent { block_height: 105 }).into(),
                ),
                (
                    SMId::Stake(key),
                    StakeEvent::StakeDataReceived(StakeDataReceivedEvent {
                        stake_funds: OutPoint::null(),
                        unstaking_image: sha256::Hash::hash(&[7; 32]),
                        unstaking_output_desc: random_p2tr_desc(),
                    })
                    .into(),
                ),
            ])
            .unwrap();
        applicator.finish();
        let before = registry.get_stake(&key).unwrap().clone();
        assert!(matches!(
            before.state(),
            StakeState::StakeGraphGenerated { .. }
        ));
        assert_eq!(before.state().last_processed_block_height(), Some(105));
        let mut applicator = Applicator::new(&mut registry, Some(0));
        for _ in 0..2 {
            assert!(
                !applicator
                    .initialize_stake(key, table.clone().into_public(), 150)
                    .unwrap()
            );
        }
        let BatchOutput { duties, tracker } = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
        assert_eq!(registry.get_stake(&key), Some(&before));
    }

    #[test]
    fn conflicting_initialization_reports_exact_stake_without_overwriting_it() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(3, 0);
        let key = StakeKey {
            covenant: CovenantId::from_operator_table(&table, 200).unwrap(),
            operator: 0,
        };
        let mut applicator = Applicator::new(&mut registry, Some(0));
        assert!(
            applicator
                .initialize_stake(key, table.clone().into_public(), 100)
                .unwrap()
        );
        applicator.finish();
        let before = registry.get_stake(&key).unwrap().clone();
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
        let error = applicator
            .initialize_stake(key, conflicting, 150)
            .unwrap_err();
        assert!(
            matches!(error, ProcessError::RegistryInsert(RegistryInsertError::CovenantMembershipMismatch(actual)) if actual == key)
        );
        assert!(error.to_string().contains(&key.to_string()));
        let BatchOutput { duties, tracker } = applicator.finish();
        assert!(duties.is_empty());
        assert!(tracker.into_batches().is_empty());
        assert_eq!(registry.get_stake(&key), Some(&before));
    }

    #[test]
    fn initialization_without_local_membership_creates_no_participant_stakes() {
        for local_operator in [None, Some(99)] {
            let mut registry = test_empty_registry();
            let table = test_operator_table(3, 0);
            let covenant = CovenantId::from_operator_table(&table, 200).unwrap();
            let mut applicator = Applicator::new(&mut registry, local_operator);
            for operator in table.operator_idxs() {
                assert!(
                    !applicator
                        .initialize_stake(
                            StakeKey { covenant, operator },
                            table.clone().into_public(),
                            100,
                        )
                        .unwrap()
                );
            }
            let BatchOutput { duties, tracker } = applicator.finish();
            assert!(duties.is_empty());
            assert!(tracker.into_batches().is_empty());
            assert_eq!(registry.num_stakes(), 0);
        }
    }
}
