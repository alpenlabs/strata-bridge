//! Contains functionality related to persisting data to disk for crash recovery.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Instant,
};

use strata_asm_bridge_types::SafeHarbourAddress;
use strata_bridge_db::{fdb::client::FdbClient, traits::BridgeDb, types::WriteBatch};
use thiserror::Error;
use tracing::error;

use crate::{
    observability,
    sm_registry::{RegistryInsertError, SMConfig, SMRegistry},
    sm_types::SMId,
};

/// An internal ID for tracking persistence batches.
type GroupId = usize;

/// Tracks which state machines must be persisted together based on signal causality.
#[derive(Debug, Clone, Default)]
pub struct PersistenceTracker {
    /// The next group ID to use for a new batch of persistence operations.
    next_group_id: GroupId,

    /// A mapping from group IDs to the set of state machine IDs that are being persisted in that
    /// batch.
    groups: HashMap<GroupId, BTreeSet<SMId>>,

    /// A mapping from state machine IDs to the group ID of the batch that is currently persisting
    /// that state machine.
    membership: HashMap<SMId, GroupId>,
}

impl PersistenceTracker {
    /// Creates a new empty persistence tracker.
    pub fn new() -> Self {
        Self {
            next_group_id: 0,
            groups: HashMap::new(),
            membership: HashMap::new(),
        }
    }

    /// Assign a state machine to a new group (called for each initial target).
    ///
    /// If the SM was already recorded, this is a no-op.
    pub fn record(&mut self, sm_id: SMId) {
        if self.membership.contains_key(&sm_id) {
            return;
        }

        let group_id = self.next_group_id;
        self.next_group_id += 1;

        self.groups.entry(group_id).or_default().insert(sm_id);
        self.membership.insert(sm_id, group_id);
    }

    /// Record that `source` produced a signal that reached `target`.
    ///
    /// Target joins `source`'s group, and if `target` was already in a different group, the two
    /// groups are merged.
    pub fn link(&mut self, source: SMId, target: SMId) {
        let source_group_id = match self.membership.get(&source) {
            Some(group_id) => *group_id,
            None => {
                // If the source is not recorded, we record it in a new group.
                self.record(source);
                self.membership[&source] // panic-safe because we just recorded it above
            }
        };

        let target_group_id = match self.membership.get(&target) {
            Some(group_id) => *group_id,
            None => {
                // If the target is not recorded, we record it in the source's group.
                self.groups
                    .entry(source_group_id)
                    .or_default()
                    .insert(target);
                self.membership.insert(target, source_group_id);
                return;
            }
        };

        if source_group_id == target_group_id {
            return;
        }

        // Merge the two groups by moving all members of the target group to the source group.
        let target_members = self.groups.remove(&target_group_id).unwrap_or_default();
        for member in target_members {
            self.groups
                .entry(source_group_id)
                .or_default()
                .insert(member);
            self.membership.insert(member, source_group_id);
        }
    }

    /// Consume the tracker and return independent persistence batches in unspecified order.
    pub fn into_batches(self) -> Vec<BTreeSet<SMId>> {
        self.groups.into_values().collect()
    }
}

/// Persister is responsible for persisting state machine states to disk and recovering them during
/// startup.
#[derive(Debug, Clone)]
pub struct Persister {
    db: Arc<FdbClient>,
}

impl Persister {
    /// Creates a new persister with the given database instance.
    pub const fn new(db: Arc<FdbClient>) -> Self {
        Self { db }
    }

    /// Persists the state of the given state machines to disk as a single atomic batch.
    pub async fn persist_batch(
        &self,
        batch: BTreeSet<SMId>,
        sm_registry: &SMRegistry,
    ) -> Result<(), PersistError> {
        let started = Instant::now();
        let batch_size = batch.len();
        let write_batch = match build_write_batch(batch, sm_registry) {
            Ok(write_batch) => write_batch,
            Err(error) => {
                observability::record_persistence(
                    "error",
                    observability::persist_error_class(&error),
                    started.elapsed(),
                );
                error!(%error, batch_size, "failed to build state-machine persistence batch");
                return Err(error);
            }
        };

        match self.db.persist_batch(&write_batch).await {
            Ok(()) => {
                observability::record_persistence("success", "none", started.elapsed());
                Ok(())
            }
            Err(source) => {
                let error = PersistError::DbErr(source);
                observability::record_persistence(
                    "error",
                    observability::persist_error_class(&error),
                    started.elapsed(),
                );
                error!(%error, batch_size, "failed to persist state-machine batch");
                Err(error)
            }
        }
    }

    /// Persists the frozen safe-harbour `address` to disk so the activation latch survives a
    /// restart without re-consulting the (non-final) ASM tip.
    pub async fn persist_safe_harbour(
        &self,
        address: &SafeHarbourAddress,
    ) -> Result<(), PersistError> {
        self.db
            .set_safe_harbour(address.clone())
            .await
            .map_err(PersistError::DbErr)
    }

    /// Build the entire registry using the most recently persisted state from disk.
    ///
    /// Also recovers the safe-harbour latch: if a frozen address was persisted before the
    /// restart, the registry is re-latched from it so the node stays in safe-harbour mode.
    pub async fn recover_registry(&self, config: SMConfig) -> Result<SMRegistry, PersistError> {
        // TODO: <https://alpenlabs.atlassian.net/browse/STR-4458>
        // Migrate existing stakes, graphs, and reservations before recovery, preserving funding
        // identity so the upgrade never requires replacement stake.
        let persisted = self
            .db
            .get_persisted_state()
            .await
            .map_err(PersistError::DbErr)?;
        let mut registry = SMRegistry::new(config);

        for (deposit_idx, deposit_sm) in persisted.deposits {
            registry.insert_deposit(deposit_idx, deposit_sm)?;
        }
        for (graph_idx, graph_sm) in persisted.graphs {
            registry.insert_graph(graph_idx, graph_sm)?;
        }
        for (stake_key, stake_sm) in persisted.stakes {
            if stake_key != stake_sm.context().stake_key() {
                return Err(PersistError::StakeIdentityMismatch);
            }
            registry.insert_stake(stake_sm)?;
        }
        if let Some(operator_set) = persisted.operator_set {
            registry.insert_operator_set(operator_set)?;
        }
        if let Some(address) = persisted.safe_harbour {
            registry.activate_safe_harbour(address);
        }

        Ok(registry)
    }
}

/// Error type for problems arising during persistence operations.
#[derive(Debug, Error)]
pub enum PersistError {
    /// Error indicating a failure to persist a batch of state machines to disk.
    #[error("persistence error: {0:?}")]
    DbErr(<FdbClient as BridgeDb>::Error),

    /// Error indicating duplicate or invalid registry state during recovery.
    #[error("registry invariant violation: {0}")]
    RegistryInvariant(#[from] RegistryInsertError),

    /// The stored row key conflicts with its stake context.
    #[error("stored stake key does not match its context")]
    StakeIdentityMismatch,
    /// A tracked state machine was absent when its atomic write batch was constructed.
    #[error("state machine {0} is missing from the registry during persistence")]
    MissingStateMachine(SMId),
}

fn build_write_batch(
    batch: BTreeSet<SMId>,
    sm_registry: &SMRegistry,
) -> Result<WriteBatch, PersistError> {
    let mut write_batch = WriteBatch::new();

    for sm_id in batch {
        match sm_id {
            SMId::OperatorSet => {
                let operator_set = sm_registry
                    .get_operator_set()
                    .ok_or(PersistError::MissingStateMachine(sm_id))?;
                write_batch.set_operator_set(operator_set.clone());
            }
            SMId::Deposit(deposit_idx) => {
                let deposit_sm = sm_registry
                    .get_deposit(&deposit_idx)
                    .ok_or(PersistError::MissingStateMachine(sm_id))?;
                write_batch.add_deposit(deposit_sm.clone());
            }
            SMId::Graph(graph_idx) => {
                let graph_sm = sm_registry
                    .get_graph(&graph_idx)
                    .ok_or(PersistError::MissingStateMachine(sm_id))?;
                write_batch.add_graph(graph_sm.clone());
            }
            SMId::Stake(operator_idx) => {
                let stake_sm = sm_registry
                    .get_stake(&operator_idx)
                    .ok_or(PersistError::MissingStateMachine(sm_id))?;
                write_batch.add_stake(stake_sm.clone());
            }
        }
    }

    Ok(write_batch)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use strata_bridge_primitives::types::GraphIdx;

    use super::*;
    use crate::testing::test_empty_registry;

    fn deposit(idx: u32) -> SMId {
        SMId::Deposit(idx)
    }

    fn graph(deposit: u32, operator: u32) -> SMId {
        SMId::Graph(GraphIdx { deposit, operator })
    }

    /// Helper: collect all SM IDs from all batches into a single sorted set.
    fn all_ids(batches: &[BTreeSet<SMId>]) -> BTreeSet<SMId> {
        batches.iter().flat_map(|b| b.iter().copied()).collect()
    }

    #[test]
    fn record_creates_singleton_group() {
        let mut tracker = PersistenceTracker::new();
        tracker.record(deposit(0));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].contains(&deposit(0)));
    }

    #[test]
    fn building_batch_fails_if_tracked_state_machine_is_missing() {
        let registry = test_empty_registry();
        let missing_id = deposit(99);
        let batch = BTreeSet::from([missing_id]);

        let result = build_write_batch(batch, &registry);
        let Err(error) = result else {
            panic!("missing state machine must fail the entire persistence batch");
        };

        assert!(matches!(
            error,
            PersistError::MissingStateMachine(id) if id == missing_id
        ));
    }

    #[test]
    fn record_multiple_creates_separate_groups() {
        let mut tracker = PersistenceTracker::new();
        tracker.record(deposit(0));
        tracker.record(deposit(1));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 2);
    }

    #[test]
    fn record_duplicate_is_noop() {
        let mut tracker = PersistenceTracker::new();
        tracker.record(deposit(0));
        tracker.record(deposit(0));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
    }

    #[test]
    fn link_merges_two_groups() {
        let mut tracker = PersistenceTracker::new();
        tracker.record(deposit(0));
        tracker.record(deposit(1));
        tracker.link(deposit(0), deposit(1));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].contains(&deposit(0)));
        assert!(batches[0].contains(&deposit(1)));
    }

    #[test]
    fn link_unrecorded_source_auto_records() {
        let mut tracker = PersistenceTracker::new();
        // Neither A nor B recorded yet.
        tracker.link(deposit(0), deposit(1));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].contains(&deposit(0)));
        assert!(batches[0].contains(&deposit(1)));
    }

    #[test]
    fn link_unrecorded_target_joins_source_group() {
        let mut tracker = PersistenceTracker::new();
        tracker.record(deposit(0));
        tracker.link(deposit(0), deposit(1));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].contains(&deposit(0)));
        assert!(batches[0].contains(&deposit(1)));
    }

    #[test]
    fn link_same_group_is_noop() {
        let mut tracker = PersistenceTracker::new();
        tracker.record(deposit(0));
        tracker.record(deposit(1));
        tracker.link(deposit(0), deposit(1));
        // Linking again within the same group should not duplicate.
        tracker.link(deposit(0), deposit(1));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 2);
    }

    #[test]
    fn link_transitive_merge() {
        let mut tracker = PersistenceTracker::new();
        tracker.record(deposit(0));
        tracker.record(deposit(1));
        tracker.record(deposit(2));

        tracker.link(deposit(0), deposit(1));
        tracker.link(deposit(1), deposit(2));

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 3);
    }

    #[test]
    fn link_mixed_sm_types() {
        let mut tracker = PersistenceTracker::new();
        let d = deposit(0);
        let g = graph(0, 1);

        tracker.record(d);
        tracker.record(g);
        tracker.link(d, g);

        let batches = tracker.into_batches();
        assert_eq!(batches.len(), 1);
        assert!(batches[0].contains(&d));
        assert!(batches[0].contains(&g));
    }

    #[test]
    fn into_batches_empty_returns_empty() {
        let tracker = PersistenceTracker::new();
        let batches = tracker.into_batches();
        assert!(batches.is_empty());
    }

    #[test]
    fn into_batches_preserves_all_sms() {
        let mut tracker = PersistenceTracker::new();
        let ids = vec![deposit(0), deposit(1), graph(0, 0), graph(1, 0)];
        for &id in &ids {
            tracker.record(id);
        }
        // Link some together.
        tracker.link(deposit(0), graph(0, 0));

        let batches = tracker.into_batches();
        let collected = all_ids(&batches);
        let expected: BTreeSet<SMId> = ids.into_iter().collect();
        assert_eq!(collected, expected);
    }
}

#[cfg(test)]
mod covenant_storage_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use strata_bridge_db::fdb::cfg::Config;
    use strata_bridge_sm::{
        operator_set::OperatorSetEvent,
        stake::{context::StakeSMCtx, machine::StakeSM},
    };

    use super::*;
    use crate::{
        sm_registry::{IgnoredEventReason, ProcessOutcome},
        testing::{
            N_TEST_OPERATORS, TEST_POV_IDX, test_empty_registry, test_operator_set_sm,
            test_operator_table, test_populated_registry, test_safe_harbour_address,
        },
    };

    #[test]
    fn write_batch_preserves_multiple_covenants_for_one_operator() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let mut keys = BTreeSet::new();
        for height in [100, 200] {
            let (sm, _) = StakeSM::new(StakeSMCtx::new(TEST_POV_IDX, table.clone(), height), 101);
            keys.insert(SMId::Stake(sm.context().stake_key()));
            registry.insert_stake(sm).unwrap();
        }
        let batch = build_write_batch(keys.clone(), &registry).unwrap();
        assert_eq!(batch.stakes().len(), 2);
        assert_eq!(
            batch
                .stakes()
                .iter()
                .map(|sm| SMId::Stake(sm.context().stake_key()))
                .collect::<BTreeSet<_>>(),
            keys,
        );
    }

    #[test]
    fn operator_set_cannot_be_silently_omitted_from_a_write_batch() {
        let mut registry = test_empty_registry();
        registry
            .insert_operator_set(test_operator_set_sm())
            .unwrap();
        let batch = build_write_batch(BTreeSet::from([SMId::OperatorSet]), &registry).unwrap();
        assert_eq!(batch.operator_set(), registry.get_operator_set());
        assert!(matches!(
            build_write_batch(BTreeSet::from([SMId::OperatorSet]), &test_empty_registry()),
            Err(PersistError::MissingStateMachine(SMId::OperatorSet))
        ));
    }

    #[tokio::test]
    async fn persisted_groups_restore_membership_and_historical_stakes() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let (client, guard) = FdbClient::setup(Config {
            root_directory: format!("test-persister-{suffix}"),
            ..Default::default()
        })
        .await
        .unwrap();
        let db = Arc::new(client);
        let persister = Persister::new(db.clone());
        let mut registry = test_populated_registry(1);
        registry
            .insert_operator_set(test_operator_set_sm())
            .unwrap();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        for height in [100, 200] {
            let (sm, _) =
                StakeSM::new(StakeSMCtx::new(TEST_POV_IDX, table.clone(), height), height);
            registry.insert_stake(sm).unwrap();
        }
        let address = test_safe_harbour_address();
        persister.persist_safe_harbour(&address).await.unwrap();
        registry.activate_safe_harbour(address);
        for id in registry.get_all_ids() {
            persister
                .persist_batch(BTreeSet::from([id]), &registry)
                .await
                .unwrap();
        }
        drop(persister);
        let restarted = Persister::new(db.clone());
        let restored = restarted
            .recover_registry(registry.cfg().clone())
            .await
            .unwrap();
        assert_eq!(restored.get_operator_set(), registry.get_operator_set());
        assert_eq!(restored.get_stake_ids(), registry.get_stake_ids());
        for key in registry.get_stake_ids() {
            assert_eq!(restored.get_stake(&key), registry.get_stake(&key));
        }
        for id in registry.get_deposit_ids() {
            assert_eq!(restored.get_deposit(&id), registry.get_deposit(&id));
        }
        for id in registry.get_graph_ids() {
            assert_eq!(restored.get_graph(&id), registry.get_graph(&id));
        }
        assert_eq!(
            restored.safe_harbour_address(),
            registry.safe_harbour_address()
        );

        let before = db.get_persisted_state().await.unwrap();
        assert!(matches!(
            restarted
                .persist_batch(
                    BTreeSet::from([SMId::OperatorSet, SMId::Deposit(99)]),
                    &registry
                )
                .await,
            Err(PersistError::MissingStateMachine(_))
        ));
        assert_eq!(db.get_persisted_state().await.unwrap(), before);

        // Only the membership group commits before a simulated interruption. Recovery must
        // replay from the lagging machines, even when membership is several blocks ahead.
        for block_height in 101..=103 {
            registry
                .process_event(
                    &SMId::OperatorSet,
                    OperatorSetEvent::NewBlock {
                        block_height,
                        exits: vec![],
                    }
                    .into(),
                )
                .unwrap();
        }
        restarted
            .persist_batch(BTreeSet::from([SMId::OperatorSet]), &registry)
            .await
            .unwrap();
        let mut recovered = restarted
            .recover_registry(registry.cfg().clone())
            .await
            .unwrap();
        assert_eq!(recovered.earliest_processed_block_height(), Some(100));
        assert_eq!(
            recovered.get_operator_set().unwrap().last_block_height(),
            103
        );
        for block_height in 101..=103 {
            assert!(matches!(
                recovered
                    .process_event(
                        &SMId::OperatorSet,
                        OperatorSetEvent::NewBlock {
                            block_height,
                            exits: vec![]
                        }
                        .into(),
                    )
                    .unwrap(),
                ProcessOutcome::Ignored {
                    reason: IgnoredEventReason::Duplicate,
                    ..
                }
            ));
        }
        assert_eq!(recovered.get_operator_set(), registry.get_operator_set());

        let key = registry.get_stake_ids()[0];
        let wrong_sm = registry
            .get_stake(&registry.get_stake_ids()[1])
            .unwrap()
            .clone();
        db.set_stake_state(key, wrong_sm).await.unwrap();
        assert!(matches!(
            restarted.recover_registry(registry.cfg().clone()).await,
            Err(PersistError::StakeIdentityMismatch)
        ));
        drop(restarted);
        drop(db);
        drop(guard);
    }
}
