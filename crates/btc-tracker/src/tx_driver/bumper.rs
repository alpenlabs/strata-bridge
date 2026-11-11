//! The bumps of CPFP packages.
//!
//! The bumper owns the bump state of each package, and with it the lease of its child. A bump
//! task borrows the state by value and hands it back with the outcome, so no state is shared
//! with a running bump.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    panic::AssertUnwindSafe,
    sync::Arc,
};

use bitcoin::Transaction;
use futures::FutureExt;
use tokio::task::{Id, JoinSet};
use tracing::error;

use super::package::PackageId;
use crate::cpfp::{BumpOutcome, CpfpBumper, CpfpStrategy, DeadlineClass};

/// Bumps that run at once. One slow signer does not hold up every other package, and no
/// trigger starts a signing round for every package at once.
pub(super) const MAX_RUNNING_BUMPS: usize = 2;

/// Runs the bumps that packages ask for, deadline packages first, and keeps their states.
pub(super) struct Bumper<B: CpfpBumper> {
    bumper: Arc<B>,
    /// The state of each package with no bump running.
    states: HashMap<PackageId, B::State>,
    /// Requests that wait for a free slot. The flag is set for a package with no deadline, so
    /// deadline packages sort first.
    queue: BTreeSet<(bool, PackageId)>,
    requests: HashMap<PackageId, (bool, Transaction, CpfpStrategy)>,
    running: HashMap<Id, PackageId>,
    /// Packages released while their bump runs. The state drops when the bump returns.
    released: HashSet<PackageId>,
    tasks: JoinSet<(PackageId, B::State, BumpOutcome)>,
}

impl<B: CpfpBumper> Bumper<B> {
    pub(super) fn new(bumper: Arc<B>) -> Self {
        Self {
            bumper,
            states: HashMap::new(),
            queue: BTreeSet::new(),
            requests: HashMap::new(),
            running: HashMap::new(),
            released: HashSet::new(),
            tasks: JoinSet::new(),
        }
    }

    /// Asks for one bump of package `id`. The bump starts at once when a slot is free.
    pub(super) fn request(&mut self, id: PackageId, tx: Transaction, strategy: CpfpStrategy) {
        let no_deadline = strategy.deadline != DeadlineClass::Deadline;
        self.queue.insert((no_deadline, id));
        self.requests.insert(id, (no_deadline, tx, strategy));
        self.start_queued();
    }

    /// Drops the state of package `id`, and with it the lease of its child. A queued request
    /// goes too. The state of a running bump drops when the bump returns.
    pub(super) fn release(&mut self, id: PackageId) {
        self.states.remove(&id);
        if let Some((no_deadline, ..)) = self.requests.remove(&id) {
            self.queue.remove(&(no_deadline, id));
        }
        if self.running.values().any(|running| *running == id) {
            self.released.insert(id);
        }
    }

    /// The outcome of the next bump to finish. `None` while no bump runs. A released package
    /// reports nothing. A bump that panicked reports [`BumpOutcome::NoPackage`], so that its
    /// package can take the next bump, and its state comes back as the panic left it: a child
    /// that reached the network keeps the lease of its inputs.
    pub(super) async fn next_outcome(&mut self) -> Option<(PackageId, BumpOutcome)> {
        loop {
            let (task, id, state, outcome) = match self.tasks.join_next_with_id().await? {
                Ok((task, (id, state, outcome))) => (task, id, state, outcome),
                Err(err) => {
                    let task = err.id();
                    let Some(&id) = self.running.get(&task) else {
                        continue;
                    };
                    error!(%err, "a bump task failed");
                    (task, id, B::State::default(), BumpOutcome::NoPackage)
                }
            };
            self.running.remove(&task);
            self.start_queued();
            if self.released.remove(&id) {
                continue;
            }
            self.states.insert(id, state);
            return Some((id, outcome));
        }
    }

    /// Starts queued bumps, deadline packages first, while a slot is free.
    fn start_queued(&mut self) {
        while self.running.len() < MAX_RUNNING_BUMPS {
            let Some((_, id)) = self.queue.pop_first() else {
                return;
            };
            let Some((_, tx, strategy)) = self.requests.remove(&id) else {
                continue;
            };
            let mut state = self.states.remove(&id).unwrap_or_default();
            let bumper = self.bumper.clone();
            let task = self.tasks.spawn(async move {
                let bump = AssertUnwindSafe(bumper.bump(&tx, &strategy, &mut state));
                let outcome = bump.catch_unwind().await.unwrap_or_else(|_| {
                    error!(?id, "a bump panicked");
                    BumpOutcome::NoPackage
                });
                (id, state, outcome)
            });
            self.running.insert(task.id(), id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::time::{sleep, timeout};

    use super::*;
    use crate::{
        cpfp::DeadlineClass,
        tx_driver::test_utils::{parent, strategy, FakeBumper},
    };

    async fn wait_until(condition: impl Fn() -> bool) {
        timeout(Duration::from_secs(5), async {
            while !condition() {
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the condition must come true");
    }

    async fn next<B: CpfpBumper>(bumper: &mut Bumper<B>) -> (PackageId, BumpOutcome) {
        timeout(Duration::from_secs(5), bumper.next_outcome())
            .await
            .expect("a bump must finish")
            .expect("a bump runs")
    }

    fn request<B: CpfpBumper>(bumper: &mut Bumper<B>, seed: u8, deadline: DeadlineClass) {
        let tx = parent(seed);
        let strategy = strategy(&tx, deadline);
        bumper.request(PackageId(seed.into()), tx, strategy);
    }

    #[tokio::test]
    async fn deadline_packages_bump_first() {
        let (fake, gate) = FakeBumper::gated(BumpOutcome::Submitted);
        let fake = Arc::new(fake);
        let mut bumper = Bumper::new(fake.clone());
        request(&mut bumper, 1, DeadlineClass::NoDeadline);
        request(&mut bumper, 2, DeadlineClass::NoDeadline);
        request(&mut bumper, 3, DeadlineClass::NoDeadline);
        request(&mut bumper, 4, DeadlineClass::Deadline);
        wait_until(|| fake.calls() == MAX_RUNNING_BUMPS).await;

        gate.add_permits(4);
        for _ in 0..4 {
            next(&mut bumper).await;
        }

        let order: Vec<_> = [1, 2, 4, 3]
            .into_iter()
            .map(|seed| parent(seed).compute_txid())
            .collect();
        assert_eq!(
            fake.bumped(),
            order,
            "the queued deadline package goes before the queued package with no deadline"
        );
    }

    #[tokio::test]
    async fn no_more_than_the_cap_runs_at_once() {
        let (fake, _gate) = FakeBumper::gated(BumpOutcome::Submitted);
        let fake = Arc::new(fake);
        let mut bumper = Bumper::new(fake.clone());
        for seed in 1..=4 {
            request(&mut bumper, seed, DeadlineClass::Deadline);
        }

        wait_until(|| fake.calls() == MAX_RUNNING_BUMPS).await;
        sleep(Duration::from_millis(20)).await;

        assert_eq!(
            fake.calls(),
            MAX_RUNNING_BUMPS,
            "the other requests wait for a slot"
        );
    }

    #[tokio::test]
    async fn a_bump_finds_the_state_of_the_last_bump() {
        let fake = Arc::new(FakeBumper::reporting(BumpOutcome::Submitted));
        let mut bumper = Bumper::new(fake.clone());

        request(&mut bumper, 1, DeadlineClass::Deadline);
        assert_eq!(
            next(&mut bumper).await,
            (PackageId(1), BumpOutcome::Submitted),
            "the outcome names its package"
        );
        request(&mut bumper, 1, DeadlineClass::Deadline);
        next(&mut bumper).await;

        assert_eq!(
            fake.saw_state(),
            vec![false, true],
            "the second bump starts from the state that the first one left"
        );
    }

    #[tokio::test]
    async fn a_release_drops_the_state() {
        let fake = Arc::new(FakeBumper::reporting(BumpOutcome::Submitted));
        let mut bumper = Bumper::new(fake.clone());
        request(&mut bumper, 1, DeadlineClass::Deadline);
        next(&mut bumper).await;
        assert_eq!(fake.leases_held(), 1, "the bumper keeps the state");

        bumper.release(PackageId(1));

        assert_eq!(fake.leases_held(), 0, "the release drops the state");
    }

    #[tokio::test]
    async fn a_release_during_a_bump_drops_its_state_when_it_returns() {
        let (fake, gate) = FakeBumper::gated(BumpOutcome::Submitted);
        let fake = Arc::new(fake);
        let mut bumper = Bumper::new(fake.clone());
        request(&mut bumper, 1, DeadlineClass::Deadline);
        wait_until(|| fake.calls() == 1).await;

        bumper.release(PackageId(1));
        gate.add_permits(1);

        let outcome = timeout(Duration::from_secs(5), bumper.next_outcome())
            .await
            .expect("the bump must finish");
        assert_eq!(outcome, None, "a released package reports no outcome");
        assert_eq!(fake.leases_held(), 0, "the returned state drops");
    }

    #[tokio::test]
    async fn a_release_cancels_a_queued_request() {
        let (fake, gate) = FakeBumper::gated(BumpOutcome::Submitted);
        let fake = Arc::new(fake);
        let mut bumper = Bumper::new(fake.clone());
        for seed in 1..=3 {
            request(&mut bumper, seed, DeadlineClass::Deadline);
        }
        wait_until(|| fake.calls() == MAX_RUNNING_BUMPS).await;

        bumper.release(PackageId(3));
        gate.add_permits(3);
        next(&mut bumper).await;
        next(&mut bumper).await;

        assert!(
            bumper.next_outcome().await.is_none(),
            "the released request never runs"
        );
        assert!(
            !fake.bumped().contains(&parent(3).compute_txid()),
            "the released package takes no bump"
        );
    }

    #[tokio::test]
    async fn dropping_the_bumper_ends_its_bumps() {
        let (fake, _gate) = FakeBumper::gated(BumpOutcome::Submitted);
        let fake = Arc::new(fake);
        let mut bumper = Bumper::new(fake.clone());
        request(&mut bumper, 1, DeadlineClass::Deadline);
        wait_until(|| fake.leases_held() == 1).await;

        drop(bumper);

        wait_until(|| fake.leases_held() == 0).await;
    }

    /// A bumper that takes a lease into the state and then panics.
    #[derive(Debug, Default)]
    struct PanickingBumper {
        lease: Arc<()>,
    }

    #[async_trait]
    impl CpfpBumper for PanickingBumper {
        type State = Option<Arc<()>>;

        async fn bump(
            &self,
            _parent: &Transaction,
            _strategy: &CpfpStrategy,
            state: &mut Self::State,
        ) -> BumpOutcome {
            *state = Some(self.lease.clone());
            panic!("the bump fails");
        }
    }

    #[tokio::test]
    async fn a_bump_that_panics_reports_no_package() {
        let mut bumper = Bumper::new(Arc::new(PanickingBumper::default()));

        request(&mut bumper, 1, DeadlineClass::Deadline);

        assert_eq!(
            next(&mut bumper).await,
            (PackageId(1), BumpOutcome::NoPackage),
            "the package hears an outcome, so its next trigger can bump again"
        );
    }

    #[tokio::test]
    async fn a_bump_that_panics_keeps_its_state() {
        let panicking = Arc::new(PanickingBumper::default());
        let mut bumper = Bumper::new(panicking.clone());
        request(&mut bumper, 1, DeadlineClass::Deadline);

        next(&mut bumper).await;

        assert_eq!(
            Arc::strong_count(&panicking.lease),
            2,
            "the state, and with it the lease of the child, outlives the panic"
        );
    }
}
