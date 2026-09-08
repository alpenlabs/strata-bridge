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
//! A duty that writes its outpoints to durable storage, or that broadcasts the spend, calls
//! [`Lease::commit`] instead. The outpoints then stay held after the value drops.
//! [`LeaseSet::release_committed`] is the only way to free them again, and the wallet also
//! frees them when a sync shows the UTXO is gone.
//!
//! # Overlapping leases
//!
//! [`LeaseSet`] records the leases that hold each outpoint, not one flat set of outpoints.
//! Two leases can hold the same outpoint at the same time. This state occurs while the driver
//! builds a replacement CPFP child: the new lease takes an input before the driver drops the
//! lease of the child that the new child replaces. The outpoint stays held until both leases
//! are gone. A flat set frees the outpoint when the first of the two leases drops, and a
//! concurrent duty can then spend an input of a live child.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
};

use bdk_wallet::bitcoin::{OutPoint, Txid};
use tracing::{debug, warn};

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
    /// it, so only [`LeaseSet::release_committed`] and the sync prune can remove it.
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
        let Some(record) = self.leases.remove(&id) else {
            return;
        };
        for outpoint in record.outpoints {
            let Some(holders) = self.holders.get_mut(&outpoint) else {
                continue;
            };
            holders.remove(&id);
            if holders.is_empty() {
                self.holders.remove(&outpoint);
            }
        }
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
pub struct LeaseSet {
    holdings: Mutex<Holdings>,
    next_id: AtomicU64,
}

impl LeaseSet {
    /// Constructs a lease set that already holds `outpoints` under
    /// [`LeaseOwner::Rehydrated`], as one committed lease.
    ///
    /// Startup reads these outpoints from durable storage. They have no live [`Lease`] value,
    /// because the duty that took the original lease ran in an earlier process.
    pub fn with_committed(outpoints: impl IntoIterator<Item = OutPoint>) -> Self {
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
    pub fn take(self: &Arc<Self>, outpoints: Vec<OutPoint>, owner: LeaseOwner) -> Lease {
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
    pub fn held(&self) -> BTreeSet<OutPoint> {
        self.lock().holders.keys().copied().collect()
    }

    /// Returns every held outpoint that `exempt` does not contain.
    ///
    /// The CPFP rebuild path passes the inputs of the child that the new child replaces. They
    /// must stay selectable, because a replacement that drops them leaves the parent with two
    /// children and breaks the TRUC one-parent-one-child shape.
    ///
    /// The result is exact when only one lease holds each outpoint in `exempt`. The CPFP
    /// rebuild path meets that condition: the inputs of the child came from a selection that
    /// skipped every held outpoint, so no other lease held them at the time, and automatic
    /// selection cannot take a held outpoint later.
    ///
    /// The condition is a requirement on the caller and not a property of the whole set.
    /// [`OperatorWallet::fund_v3_transaction_with_inputs`](crate::OperatorWallet::fund_v3_transaction_with_inputs)
    /// names its inputs and skips selection, so it can take a second lease on a held
    /// outpoint. No caller passes those outpoints here.
    pub fn held_excluding(&self, exempt: &[OutPoint]) -> BTreeSet<OutPoint> {
        self.lock()
            .holders
            .keys()
            .filter(|outpoint| !exempt.contains(outpoint))
            .copied()
            .collect()
    }

    /// Releases `outpoints` that a committed lease holds.
    ///
    /// A live [`Lease`] value keeps its outpoints through this call. Only [`Drop`] frees
    /// those. This method exists for the outpoints that startup read from durable storage,
    /// and for a duty that discards a stored reservation that it can no longer use.
    pub fn release_committed(&self, outpoints: &[OutPoint]) {
        let mut holdings = self.lock();
        for outpoint in outpoints {
            if !holdings.committed_holds(*outpoint) {
                warn!(
                    ?outpoint,
                    "released an outpoint that no committed lease holds"
                );
            }
        }
        holdings.remove_outpoints(outpoints.iter().copied(), |record| record.committed);
    }

    /// Drops every held outpoint that `live` does not contain.
    ///
    /// A wallet sync calls this method. An outpoint that leaves the spendable set was spent
    /// on chain, and the on-chain spend supersedes the local bookkeeping. The method reports
    /// the owner of each lease that loses an outpoint, because a lease that loses inputs it
    /// still expects to spend explains a later funding error.
    pub fn retain_live(&self, live: &BTreeSet<OutPoint>) {
        let mut holdings = self.lock();
        let stale: Vec<OutPoint> = holdings
            .holders
            .keys()
            .filter(|outpoint| !live.contains(outpoint))
            .copied()
            .collect();
        for outpoint in &stale {
            let owners = holdings.owners_of(*outpoint);
            debug!(
                ?outpoint,
                ?owners,
                "sync pruned a lease on a spent outpoint"
            );
        }
        holdings.remove_outpoints(stale, |_| true);
    }

    /// Records a new lease and returns its identifier.
    fn insert(&self, outpoints: Vec<OutPoint>, owner: LeaseOwner) -> LeaseId {
        let id = LeaseId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let mut holdings = self.lock();
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
/// [`Self::commit`] hands the outpoints to durable storage or to a broadcast transaction.
/// The outpoints then stay held after this value drops.
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
    /// The outpoints that this lease holds.
    pub fn outpoints(&self) -> &[OutPoint] {
        &self.outpoints
    }

    /// Keeps the outpoints held after this value drops.
    ///
    /// A duty calls this method once the outpoints are safe to hold without a live value:
    /// durable storage records them, or a broadcast transaction spends them. A later sync
    /// frees them when the spend confirms. [`LeaseSet::release_committed`] frees them if the
    /// duty must discard the record instead.
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

        set.release_committed(&[outpoint(1)]);
        assert!(set.held().is_empty());
    }

    #[test]
    fn release_committed_leaves_a_live_lease_alone() {
        let set = Arc::new(LeaseSet::default());
        let lease = set.take(vec![outpoint(1)], LeaseOwner::ClaimFunding);
        set.release_committed(&[outpoint(1)]);
        assert_eq!(
            set.held(),
            BTreeSet::from([outpoint(1)]),
            "a live lease must survive a committed-release of the same outpoint"
        );
        drop(lease);
        assert!(set.held().is_empty());
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
    fn held_excluding_keeps_every_other_lease_excluded() {
        let set = Arc::new(LeaseSet::default());
        let prior = set.take(vec![outpoint(1), outpoint(2)], LeaseOwner::ClaimFunding);
        let other = set.take(vec![outpoint(3)], LeaseOwner::StakeFunding);

        assert_eq!(
            set.held_excluding(prior.outpoints()),
            BTreeSet::from([outpoint(3)]),
            "the prior lease's inputs are selectable again; another lease's are not"
        );
        assert_eq!(
            set.held_excluding(&[]),
            BTreeSet::from([outpoint(1), outpoint(2), outpoint(3)]),
            "an empty exemption excludes everything held"
        );
        drop((prior, other));
    }

    #[test]
    fn retain_live_drops_leases_on_spent_outpoints() {
        let set = Arc::new(LeaseSet::default());
        let lease = set.take(vec![outpoint(1), outpoint(2)], LeaseOwner::ClaimFunding);
        set.retain_live(&BTreeSet::from([outpoint(2)]));
        assert_eq!(set.held(), BTreeSet::from([outpoint(2)]));
        assert_eq!(
            lease.outpoints(),
            [outpoint(1), outpoint(2)],
            "the value keeps its own record of what it asked for"
        );
        drop(lease);
        assert!(set.held().is_empty());
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
        set.release_committed(&[outpoint(1)]);
        assert_eq!(set.held(), BTreeSet::from([outpoint(2)]));
    }
}
