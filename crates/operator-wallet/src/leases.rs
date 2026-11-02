//! Lease bookkeeping for wallet outpoints.
//!
//! A lease holds outpoints and keeps them out of input selection. Two duties that run at the
//! same time therefore cannot spend one UTXO twice.
//!
//! [`Lease`] releases its outpoints when it drops. A duty keeps the value for as long as the
//! outpoints must stay held. A duty that fails at any step drops the lease on the error path,
//! so no error path needs an explicit release call, and a new early return cannot strand a
//! UTXO.
//!
//! A duty that hands its outpoints to something that outlives it calls [`Lease::commit`] instead,
//! which states when. The outpoints then stay held after the value drops. Only a sync that shows a
//! buried spend frees them. A spend in the mempool or in an unburied block does not free them,
//! because a reorg can still undo that spend.
//!
//! # Overlapping leases
//!
//! The wallet records the leases that hold each outpoint, not one flat set of outpoints.
//! Two leases can hold the same outpoint at the same time. This state occurs while the driver
//! builds a replacement CPFP child: the new lease takes an input before the driver drops the
//! lease of the child that the new child replaces. The outpoint stays held until both leases
//! are gone. A flat set frees the outpoint when the first of the two leases drops, and a
//! concurrent duty can then spend an input of a live child.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard},
};

use bdk_wallet::bitcoin::{OutPoint, Txid};
use tracing::debug;

/// Identifies one lease inside a [`LeaseSet`].
///
/// Private to this module. Callers hold a [`Lease`] value, which is the only handle they
/// need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct LeaseId(u64);

/// The duty that holds a lease.
///
/// The wallet records this value against each live lease. A lease that outlives its duty then
/// names its holder in the log line that reports the release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseOwner {
    /// Inputs of a transaction that refills the pool of claim-funding UTXOs.
    ClaimFundingRefill,
    /// One reserved-wallet UTXO that funds the claim of one graph.
    ClaimFunding,
    /// Inputs of the stake funding reservation.
    StakeFunding,
    /// Inputs of the withdrawal fulfillment transaction of one deposit.
    WithdrawalFulfillment,
    /// The general-wallet UTXO that pays for an unstaking burn transaction.
    UnstakingBurn,
    /// The general-wallet UTXO that pays for a bridge proof transaction.
    BridgeProof,
    /// Funding inputs of the CPFP child of one parent transaction.
    CpfpChild {
        /// Txid of the parent that the child pays for.
        parent: Txid,
    },
    /// Read from durable storage at startup. The duty that took the original lease is not
    /// recorded, because durable storage keeps outpoints and not owners.
    Rehydrated,
}

/// State of one live lease.
#[derive(Debug)]
struct LeaseRecord {
    owner: LeaseOwner,
    outpoints: BTreeSet<OutPoint>,
    /// True after [`Lease::commit`]. A committed record has no live [`Lease`] value behind
    /// it, so only the sync prune can remove it.
    committed: bool,
}

/// The live leases and the outpoints that they hold.
#[derive(Debug, Default)]
struct Holdings {
    /// Owner and outpoints of each live lease.
    leases: BTreeMap<LeaseId, LeaseRecord>,
    /// The leases that hold each outpoint. An outpoint is unavailable for selection while
    /// its entry exists.
    holders: BTreeMap<OutPoint, BTreeSet<LeaseId>>,
    /// The identifier of the next lease.
    next_id: u64,
}

impl Holdings {
    /// Removes `outpoints` from every lease that holds them and that `predicate` accepts.
    /// Drops a lease record that keeps no outpoints after the removal.
    fn remove_outpoints(
        &mut self,
        outpoints: impl IntoIterator<Item = OutPoint>,
        predicate: impl Fn(&LeaseRecord) -> bool,
    ) {
        for outpoint in outpoints {
            let Some(holders) = self.holders.get(&outpoint) else {
                continue;
            };
            let affected: Vec<LeaseId> = holders
                .iter()
                .copied()
                .filter(|id| self.leases.get(id).is_some_and(&predicate))
                .collect();
            for id in affected {
                self.detach(id, outpoint);
            }
        }
    }

    /// Removes one outpoint from one lease, and drops either side that becomes empty.
    fn detach(&mut self, id: LeaseId, outpoint: OutPoint) {
        if let Some(record) = self.leases.get_mut(&id) {
            record.outpoints.remove(&outpoint);
            if record.outpoints.is_empty() {
                self.leases.remove(&id);
            }
        }
        if let Some(holders) = self.holders.get_mut(&outpoint) {
            holders.remove(&id);
            if holders.is_empty() {
                self.holders.remove(&outpoint);
            }
        }
    }

    /// Removes one lease and every outpoint that only it holds.
    fn remove_lease(&mut self, id: LeaseId) {
        let outpoints = self
            .leases
            .get(&id)
            .map(|record| record.outpoints.clone())
            .unwrap_or_default();
        for outpoint in outpoints {
            self.detach(id, outpoint);
        }
        // `detach` removes a record that it empties, and a lease on no outpoints never reaches it.
        self.leases.remove(&id);
    }

    /// The owners of every lease that holds `outpoint`.
    fn owners_of(&self, outpoint: OutPoint) -> Vec<LeaseOwner> {
        self.holders
            .get(&outpoint)
            .into_iter()
            .flatten()
            .filter_map(|id| self.leases.get(id).map(|record| record.owner))
            .collect()
    }

    /// Whether a committed lease holds `outpoint`.
    fn committed_holds(&self, outpoint: OutPoint) -> bool {
        self.holders.get(&outpoint).is_some_and(|holders| {
            holders
                .iter()
                .any(|id| self.leases.get(id).is_some_and(|record| record.committed))
        })
    }
}

/// Shared record of the outpoints that duties hold.
///
/// The wallet keeps one of these behind an [`Arc`] and hands out [`Lease`] values against it.
/// The lock inside is a [`std::sync::Mutex`] and not a `tokio` mutex, because [`Lease`]
/// releases its outpoints in [`Drop`], which cannot await. No code path holds the lock across
/// an await point.
#[derive(Debug, Default)]
pub(crate) struct LeaseSet {
    holdings: Mutex<Holdings>,
}

impl LeaseSet {
    /// Constructs a lease set that already holds `outpoints` under
    /// [`LeaseOwner::Rehydrated`], as one committed lease.
    ///
    /// Startup reads these outpoints from durable storage. They have no live [`Lease`] value,
    /// because the duty that took the original lease ran in an earlier process.
    pub(crate) fn with_committed(outpoints: impl IntoIterator<Item = OutPoint>) -> Self {
        let set = Self::default();
        let outpoints: Vec<OutPoint> = outpoints.into_iter().collect();
        if !outpoints.is_empty() {
            let id = set.insert(outpoints, LeaseOwner::Rehydrated);
            set.commit(id);
        }
        set
    }

    /// Takes a lease on `outpoints` for `owner`.
    ///
    /// The returned value releases the outpoints when it drops.
    pub(crate) fn take(self: &Arc<Self>, outpoints: Vec<OutPoint>, owner: LeaseOwner) -> Lease {
        let id = self.insert(outpoints.clone(), owner);
        Lease {
            set: Arc::clone(self),
            id,
            outpoints,
            owner,
            committed: false,
        }
    }

    /// Returns every outpoint that a lease holds.
    pub(crate) fn held(&self) -> BTreeSet<OutPoint> {
        self.lock().holders.keys().copied().collect()
    }

    /// Returns every outpoint that a lease outside `excluded` holds.
    ///
    /// The scope is the leases, not their outpoints. Another lease can hold an outpoint that one
    /// of `excluded` also names, and that outpoint stays out of reach: a reorg undid the confirmed
    /// spend that pruned the record of the excluded lease and a duty took the outpoint, or a
    /// stored reservation holds the same outpoint.
    pub(crate) fn held_excluding(&self, excluded: &[&Lease]) -> BTreeSet<OutPoint> {
        self.lock()
            .holders
            .iter()
            .filter(|(_, holders)| {
                holders
                    .iter()
                    .any(|id| excluded.iter().all(|lease| lease.id != *id))
            })
            .map(|(outpoint, _)| *outpoint)
            .collect()
    }

    /// Drops every lease on `spent`, committed or not.
    ///
    /// A wallet sync calls this method with the held outpoints that show a buried spend. That
    /// spend supersedes the local bookkeeping. An unburied spend does not: a reorg can still undo
    /// it, and the outpoint then returns while a durable record names it. The method
    /// reports the owner of each lease that loses an outpoint, because a lease that loses inputs
    /// it still expects to spend explains a later funding error.
    pub(crate) fn prune_spent(&self, spent: &BTreeSet<OutPoint>) {
        let mut holdings = self.lock();
        for outpoint in spent {
            let owners = holdings.owners_of(*outpoint);
            debug!(
                ?outpoint,
                ?owners,
                "sync pruned a lease on an outpoint with a buried spend"
            );
        }
        holdings.remove_outpoints(spent.iter().copied(), |_| true);
    }

    /// Records a new lease and returns its identifier.
    fn insert(&self, outpoints: Vec<OutPoint>, owner: LeaseOwner) -> LeaseId {
        let mut holdings = self.lock();
        let id = LeaseId(holdings.next_id);
        holdings.next_id += 1;
        for outpoint in &outpoints {
            holdings.holders.entry(*outpoint).or_default().insert(id);
        }
        holdings.leases.insert(
            id,
            LeaseRecord {
                owner,
                outpoints: outpoints.into_iter().collect(),
                committed: false,
            },
        );
        id
    }

    /// Marks the lease as committed, so its outpoints outlive the [`Lease`] value.
    ///
    /// Drops the lease instead when a committed lease already holds every one of its
    /// outpoints. The set of held outpoints is the same either way, and the record count
    /// stays bounded. Without this check, each retry of a duty that reuses a stored
    /// reservation adds one more permanent record for the same outpoints, and nothing in
    /// production removes it before the spend confirms.
    fn commit(&self, id: LeaseId) {
        let mut holdings = self.lock();
        let Some(record) = holdings.leases.get(&id) else {
            return;
        };
        let redundant = record
            .outpoints
            .iter()
            .all(|outpoint| holdings.committed_holds(*outpoint));
        if redundant {
            holdings.remove_lease(id);
            return;
        }
        if let Some(record) = holdings.leases.get_mut(&id) {
            record.committed = true;
        }
    }

    /// Frees every outpoint that only the lease `id` holds. Called from [`Lease::drop`].
    fn release(&self, id: LeaseId) {
        self.lock().remove_lease(id);
    }

    /// The number of live lease records. Test-only: the record count is not observable
    /// through [`Self::held`], because a repeated commit and a single commit hold the same
    /// outpoints.
    #[cfg(test)]
    fn lease_count(&self) -> usize {
        self.lock().leases.len()
    }

    /// Locks the holdings and recovers from a poisoned lock.
    ///
    /// A poisoned lock means a panic happened inside one of the short critical sections of
    /// this module. The data stays consistent, because no step between the two map writes of
    /// a critical section can panic: the closures are comparisons, and the log statements run
    /// before any mutation. A panic in [`Lease::drop`] must not cascade into every later
    /// wallet operation.
    fn lock(&self) -> MutexGuard<'_, Holdings> {
        self.holdings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Holds outpoints against input selection until it drops.
///
/// A duty keeps this value alive for as long as it needs the outpoints. The error paths of
/// the duty need no release call, because the value drops with the stack frame.
///
/// [`Self::commit`] keeps the outpoints held after this value drops, and it states when a duty
/// does that.
#[must_use = "the lease releases its outpoints as soon as the value drops"]
#[derive(Debug)]
pub struct Lease {
    set: Arc<LeaseSet>,
    id: LeaseId,
    outpoints: Vec<OutPoint>,
    owner: LeaseOwner,
    committed: bool,
}

impl Lease {
    /// The outpoints that this lease took. A sync drops those with a buried spend from the hold.
    pub fn outpoints(&self) -> &[OutPoint] {
        &self.outpoints
    }

    /// Keeps the outpoints held after this value drops.
    ///
    /// A duty commits when a durable record names the outpoints, or when the result of a broadcast
    /// is unknown and a sync cannot settle it now. After a broadcast that the node accepted, the
    /// duty keeps the value until a sync sees the spend, and then drops it: the view hides a live
    /// spend, and it returns the outpoints of a spend that dies.
    ///
    /// A later sync frees committed outpoints once the spend is buried. A spend that dies frees
    /// nothing: the outpoint
    /// stays held for the life of the process, which a stored record needs, because a retry
    /// spends that outpoint again.
    pub fn commit(mut self) {
        self.set.commit(self.id);
        self.committed = true;
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        debug!(
            owner = ?self.owner,
            outpoints = ?self.outpoints,
            "released a lease"
        );
        self.set.release(self.id);
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::hashes::Hash;

    use super::*;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        }
    }

    #[test]
    fn a_dropped_lease_frees_its_outpoints() {
        let set = Arc::new(LeaseSet::default());
        let lease = set.take(vec![outpoint(1), outpoint(2)], LeaseOwner::StakeFunding);
        assert_eq!(set.held().len(), 2);
        drop(lease);
        assert!(set.held().is_empty());
    }

    #[test]
    fn a_committed_lease_outlives_its_value() {
        let set = Arc::new(LeaseSet::default());
        let lease = set.take(vec![outpoint(1)], LeaseOwner::ClaimFunding);
        lease.commit();
        assert_eq!(set.held(), BTreeSet::from([outpoint(1)]));

        set.prune_spent(&BTreeSet::from([outpoint(1)]));
        assert!(
            set.held().is_empty(),
            "only a sync prune ends a committed lease"
        );
    }

    #[test]
    fn an_outpoint_two_leases_hold_survives_the_first_drop() {
        let set = Arc::new(LeaseSet::default());
        let shared = outpoint(1);
        let old = set.take(
            vec![shared, outpoint(2)],
            LeaseOwner::CpfpChild {
                parent: Txid::from_byte_array([9; 32]),
            },
        );
        let new = set.take(
            vec![shared, outpoint(3)],
            LeaseOwner::CpfpChild {
                parent: Txid::from_byte_array([9; 32]),
            },
        );

        drop(old);
        assert_eq!(
            set.held(),
            BTreeSet::from([shared, outpoint(3)]),
            "the replacement child's inputs must stay held; only outpoint 2 is freed"
        );
        drop(new);
        assert!(set.held().is_empty());
    }

    #[test]
    fn a_prune_drops_leases_on_spent_outpoints() {
        let set = Arc::new(LeaseSet::default());
        let lease = set.take(vec![outpoint(1), outpoint(2)], LeaseOwner::ClaimFunding);
        set.prune_spent(&BTreeSet::from([outpoint(1)]));
        assert_eq!(set.held(), BTreeSet::from([outpoint(2)]));
        assert_eq!(
            lease.outpoints(),
            [outpoint(1), outpoint(2)],
            "the value keeps its own record of what it asked for"
        );
        drop(lease);
        assert!(set.held().is_empty());
    }

    #[test]
    fn held_excluding_leaves_out_only_what_that_lease_alone_holds() {
        let set = Arc::new(LeaseSet::default());
        let replaced = set.take(vec![outpoint(1), outpoint(2)], LeaseOwner::ClaimFunding);
        let other = set.take(vec![outpoint(2), outpoint(3)], LeaseOwner::StakeFunding);
        assert_eq!(
            set.held_excluding(&[&replaced]),
            BTreeSet::from([outpoint(2), outpoint(3)]),
            "an outpoint another lease holds stays held"
        );
        drop(other);
        assert!(set.held_excluding(&[&replaced]).is_empty());
    }

    /// A confirmed spend pruned the record of the replaced lease, a reorg undid that spend, and
    /// another duty took the outpoint. The value still names it, and it must stay out of reach.
    #[test]
    fn held_excluding_keeps_an_outpoint_that_a_later_lease_took_over() {
        let set = Arc::new(LeaseSet::default());
        let replaced = set.take(vec![outpoint(1)], LeaseOwner::ClaimFunding);
        set.prune_spent(&BTreeSet::from([outpoint(1)]));
        let _other = set.take(vec![outpoint(1)], LeaseOwner::StakeFunding);
        assert_eq!(
            set.held_excluding(&[&replaced]),
            BTreeSet::from([outpoint(1)])
        );
    }

    /// A child that spends only the parent output holds no wallet input, and its lease is empty.
    #[test]
    fn a_dropped_lease_on_no_outpoints_leaves_no_record() {
        let set = Arc::new(LeaseSet::default());
        drop(set.take(Vec::new(), LeaseOwner::ClaimFunding));
        assert_eq!(set.lease_count(), 0);
        set.take(Vec::new(), LeaseOwner::ClaimFunding).commit();
        assert_eq!(set.lease_count(), 0);
    }

    /// A duty that reuses a stored reservation commits a fresh lease on every retry. Each of
    /// those commits must collapse into the record that already holds the outpoints, or the
    /// record count grows with the retry count and nothing removes the surplus.
    #[test]
    fn a_repeated_commit_of_held_outpoints_adds_no_record() {
        let set = Arc::new(LeaseSet::default());
        for _ in 0..5 {
            set.take(vec![outpoint(1)], LeaseOwner::StakeFunding)
                .commit();
        }
        assert_eq!(set.held(), BTreeSet::from([outpoint(1)]));
        assert_eq!(
            set.lease_count(),
            1,
            "repeat commits must not stack records"
        );
    }

    #[test]
    fn a_commit_that_adds_an_outpoint_keeps_its_record() {
        let set = Arc::new(LeaseSet::default());
        set.take(vec![outpoint(1)], LeaseOwner::StakeFunding)
            .commit();
        set.take(vec![outpoint(1), outpoint(2)], LeaseOwner::StakeFunding)
            .commit();
        assert_eq!(set.held(), BTreeSet::from([outpoint(1), outpoint(2)]));
        assert_eq!(
            set.lease_count(),
            2,
            "a commit that holds a new outpoint keeps its own record"
        );
    }

    #[test]
    fn with_committed_seeds_rehydrated_outpoints() {
        let set = LeaseSet::with_committed([outpoint(1), outpoint(2)]);
        assert_eq!(set.held(), BTreeSet::from([outpoint(1), outpoint(2)]));
        set.prune_spent(&BTreeSet::from([outpoint(1)]));
        assert_eq!(set.held(), BTreeSet::from([outpoint(2)]));
    }
}
