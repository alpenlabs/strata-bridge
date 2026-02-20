//! Contains functionality related to persisting data to disk for crash recovery.

use std::collections::{BTreeSet, HashMap};

use strata_bridge_db2::{traits::BridgeDb, types::WriteBatch};
use thiserror::Error;
use tracing::error;

use crate::{
    sm_registry::{SMConfig, SMRegistry},
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

    /// Consume the tracker and return persistence batches.
    pub fn into_batches(self) -> Vec<BTreeSet<SMId>> {
        self.groups.into_values().collect()
    }
}

/// Persister is responsible for persisting state machine states to disk and recovering them during
/// startup.
#[derive(Debug)]
pub struct Persister<Db>
where
    Db: BridgeDb,
{
    db: Db,
}

impl<Db: BridgeDb> Persister<Db> {
    /// Creates a new persister with the given database instance.
    pub const fn new(db: Db) -> Self {
        Self { db }
    }

    /// Persists the state of the given state machines to disk as a single atomic batch.
    pub async fn persist_batch(
        &self,
        batch: BTreeSet<SMId>,
        sm_registry: &SMRegistry,
    ) -> Result<(), PersistError<Db>> {
        let write_batch = batch
            .into_iter()
            .fold(WriteBatch::new(), |mut write_batch, sm_id| {
                match sm_id {
                    SMId::Deposit(deposit_idx) => {
                        if let Some(deposit_sm) = sm_registry.get_deposit(&deposit_idx) {
                            write_batch.add_deposit(deposit_sm.clone());
                        } else {
                            error!("Attempted to persist deposit state machine with index {deposit_idx}, but it was not found in the registry");
                        }
                    }
                    SMId::Graph(graph_idx) => {
                        if let Some(graph_sm) = sm_registry.get_graph(&graph_idx) {
                            write_batch.add_graph(graph_sm.clone());
                        } else {
                            error!("Attempted to persist graph state machine with index {graph_idx}, but it was not found in the registry");
                        }
                    }
                }

                write_batch
            });

        self.db
            .persist_batch(&write_batch)
            .await
            .map_err(PersistError::DbErr)
    }

    /// Build the entire registry using the most recently persisted state from disk.
    pub async fn recover_registry(&self, config: SMConfig) -> Result<SMRegistry, PersistError<Db>> {
        let mut registry = SMRegistry::new(config);

        self.db
            .get_all_deposit_states()
            .await
            .map_err(PersistError::DbErr)?
            .into_iter()
            .for_each(|(deposit_idx, deposit_sm)| {
                registry.insert_deposit(deposit_idx, deposit_sm);
            });

        self.db
            .get_all_graph_states()
            .await
            .map_err(PersistError::DbErr)?
            .into_iter()
            .for_each(|(graph_idx, graph_sm)| {
                registry.insert_graph(graph_idx, graph_sm);
            });

        Ok(registry)
    }
}

/// Error type for problems arising during persistence operations.
#[derive(Debug, Error)]
pub enum PersistError<Db: BridgeDb> {
    /// Error indicating a failure to persist a batch of state machines to disk.
    #[error("persistence error: {0}")]
    DbErr(Db::Error),
}
