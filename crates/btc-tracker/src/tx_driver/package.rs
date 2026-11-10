//! The lifecycle of one package: a parent and the child that bumps it.
//!
//! [`Package::step`] is a pure transition from one [`Event`] to the next package and the
//! [`Action`]s that the tracker runs. The machine knows nothing of the callers that wait on the
//! parent: it reports its status when the status changes or a job joins, and it reports its end.
//! The tracker answers the callers.

use bitcoind_async_client::error::ClientError;

use crate::{
    cpfp::{BumpOutcome, CpfpStrategy, FirstBump},
    event::TxStatus,
};

/// Identifies one package for its whole life. A new job for a txid whose package ended opens a
/// package with a new id, so a late result for the old one cannot touch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct PackageId(pub(super) u64);

/// One package and where the driver last saw it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Package {
    cpfp: Cpfp,
    /// Whether a bump that this package asked for has not reported yet.
    bump_running: bool,
    state: PackageState,
}

/// Whether the package takes CPFP bumps.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Cpfp {
    /// No job asked for CPFP.
    Bare,
    /// The bumper keeps the package at the target.
    Armed(CpfpStrategy),
    /// The bumper reported that the parent cannot carry a child. Every later bump would fail
    /// the same way, so a later job does not arm the package again.
    GaveUp,
}

/// Where the driver last saw the parent.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum PackageState {
    /// In no mempool and in no block since `cause`. `rejection` is the error of the last bare
    /// send, kept for the case that the package later loses its CPFP strategy.
    Pending {
        cause: PendingCause,
        rejection: Option<ClientError>,
    },
    InMempool,
    /// In a block, not yet buried. No bumps run.
    Mined(TxStatus),
    /// The package is over. The tracker drops it after its [`Action::Ended`].
    Ended,
}

/// Why a package is pending. It names the error that a rejected bare send reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingCause {
    /// The first send of the parent.
    Publish,
    /// The parent left the mempool or its block.
    Eviction,
}

/// The result of a bare send.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum BroadcastResult {
    /// The node holds the parent in its mempool.
    Accepted,
    /// The node rejected the parent because it is already in a block.
    Known(TxStatus),
    /// The node rejected the parent.
    Rejected(ClientError),
}

/// One input to [`Package::step`].
#[derive(Debug, Clone)]
pub(super) enum Event {
    /// A job for this parent joined. Its caller hears the status of the package, and `cpfp`, the
    /// strategy of the job, arms a bare package.
    Joined { cpfp: Option<CpfpStrategy> },
    /// A status of the parent from ZMQ, from a job, or from the read on each block. `Unknown`
    /// means that it left the mempool.
    Seen(TxStatus),
    /// A block connected, after the read of every package on that block.
    Block,
    /// The bump interval elapsed.
    Tick,
    /// A bare send that this package asked for finished.
    Broadcasted(BroadcastResult),
    /// A bump that this package asked for finished.
    Bumped(BumpOutcome),
}

/// One output of [`Package::step`].
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Action {
    /// Send the parent bare.
    Broadcast,
    /// Run one bump of the parent.
    Bump,
    /// Drop the bump state of the package, and with it the lease of its child.
    Release,
    /// Report a status of the parent. The tracker answers each caller whose condition the status
    /// meets, and the others keep waiting.
    Report(TxStatus),
    /// The package is over. The tracker answers every caller that still waits.
    Ended(Ending),
}

/// How a package ended.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Ending {
    /// The parent is buried.
    Buried,
    /// The node rejected the bare parent and no bump can carry it.
    Rejected {
        cause: PendingCause,
        error: ClientError,
    },
}

impl Package {
    /// Opens a package for a parent that a job read at `status`. A failed read counts as
    /// `Unknown`, and the node decides at the send.
    pub(super) fn open(cpfp: Option<CpfpStrategy>, status: TxStatus) -> (Self, Vec<Action>) {
        let mut package = Self {
            cpfp: cpfp.map_or(Cpfp::Bare, Cpfp::Armed),
            bump_running: false,
            state: PackageState::Pending {
                cause: PendingCause::Publish,
                rejection: None,
            },
        };
        let actions = match status {
            TxStatus::Unknown => vec![Action::Broadcast],
            TxStatus::Mempool => package.enter_mempool(),
            status => package.observe(status),
        };
        (package, actions)
    }

    /// The transition function. An ended package ignores every event.
    pub(super) fn step(mut self, event: Event) -> (Self, Vec<Action>) {
        if self.state == PackageState::Ended {
            return (self, Vec::new());
        }
        let actions = match event {
            Event::Joined { cpfp } => self.join(cpfp),
            Event::Seen(status) => self.observe(status),
            Event::Block | Event::Tick => self.bump().into_iter().collect(),
            Event::Broadcasted(result) => self.broadcasted(result),
            Event::Bumped(outcome) => self.bumped(outcome),
        };
        (self, actions)
    }

    /// The status that the state stands for. A pending or ended package stands for none, which
    /// reads as `Unknown`.
    fn status(&self) -> TxStatus {
        match &self.state {
            PackageState::InMempool => TxStatus::Mempool,
            PackageState::Mined(status) => status.clone(),
            PackageState::Pending { .. } | PackageState::Ended => TxStatus::Unknown,
        }
    }

    /// Reports the status that the package stands for, if it stands for one.
    fn report(&self) -> Option<Action> {
        let status = self.status();
        (status != TxStatus::Unknown).then_some(Action::Report(status))
    }

    /// The strategy that the bumper runs, while the package is armed.
    pub(super) const fn strategy(&self) -> Option<&CpfpStrategy> {
        match &self.cpfp {
            Cpfp::Armed(strategy) => Some(strategy),
            Cpfp::Bare | Cpfp::GaveUp => None,
        }
    }

    const fn evicted() -> PackageState {
        PackageState::Pending {
            cause: PendingCause::Eviction,
            rejection: None,
        }
    }

    /// A job joined. Its caller hears the status of the package, and the job's strategy arms a
    /// bare package. A package that the bumper gave up on stays as it is, and an armed package
    /// keeps its first strategy.
    fn join(&mut self, cpfp: Option<CpfpStrategy>) -> Vec<Action> {
        let mut actions: Vec<_> = self.report().into_iter().collect();
        if let (Cpfp::Bare, Some(strategy)) = (&self.cpfp, cpfp) {
            self.cpfp = Cpfp::Armed(strategy);
            actions.extend(self.bump_at_publish());
        }
        actions
    }

    /// Follows a status of the parent. A parent that left the mempool or its block goes back
    /// bare, unless the package already waits on a send or a bump.
    fn observe(&mut self, status: TxStatus) -> Vec<Action> {
        match status {
            TxStatus::Buried { .. } => {
                let mut actions = vec![Action::Report(status)];
                actions.extend(self.end(Ending::Buried));
                actions
            }
            TxStatus::Mined { .. } => {
                if self.state == PackageState::Mined(status.clone()) {
                    return Vec::new();
                }
                self.state = PackageState::Mined(status.clone());
                vec![Action::Report(status)]
            }
            TxStatus::Mempool => {
                if self.state == PackageState::InMempool {
                    return Vec::new();
                }
                self.state = PackageState::InMempool;
                vec![Action::Report(TxStatus::Mempool)]
            }
            TxStatus::Unknown => match self.state {
                PackageState::InMempool | PackageState::Mined(_) => {
                    self.state = Self::evicted();
                    vec![Action::Broadcast]
                }
                PackageState::Pending { .. } | PackageState::Ended => Vec::new(),
            },
        }
    }

    /// The parent reached a mempool through a bare send or a job's read. A presigned parent
    /// takes its first bump now.
    fn enter_mempool(&mut self) -> Vec<Action> {
        let mut actions = self.observe(TxStatus::Mempool);
        actions.extend(self.bump_at_publish());
        actions
    }

    /// Applies the result of a bare send. A result that arrives after the package moved on
    /// changes nothing.
    fn broadcasted(&mut self, result: BroadcastResult) -> Vec<Action> {
        let PackageState::Pending { cause, .. } = self.state else {
            return Vec::new();
        };
        match result {
            BroadcastResult::Accepted => self.enter_mempool(),
            BroadcastResult::Known(status) => self.observe(status),
            BroadcastResult::Rejected(error) => match self.cpfp {
                Cpfp::Armed(_) => {
                    self.state = PackageState::Pending {
                        cause,
                        rejection: Some(error),
                    };
                    self.bump().into_iter().collect()
                }
                Cpfp::Bare | Cpfp::GaveUp => self.end(Ending::Rejected { cause, error }),
            },
        }
    }

    /// Applies the outcome of a bump. A bump with no package changes no state: the next
    /// trigger retries.
    fn bumped(&mut self, outcome: BumpOutcome) -> Vec<Action> {
        self.bump_running = false;
        match outcome {
            BumpOutcome::Submitted | BumpOutcome::ParentIsLive => {
                if matches!(self.state, PackageState::Pending { .. }) {
                    self.observe(TxStatus::Mempool)
                } else {
                    Vec::new()
                }
            }
            BumpOutcome::NoPackage => Vec::new(),
            BumpOutcome::Unbumpable => {
                if !matches!(self.cpfp, Cpfp::Armed(_)) {
                    return Vec::new();
                }
                self.cpfp = Cpfp::GaveUp;
                let mut actions = vec![Action::Release];
                if let PackageState::Pending {
                    cause,
                    rejection: Some(error),
                } = &self.state
                {
                    let ending = Ending::Rejected {
                        cause: *cause,
                        error: error.clone(),
                    };
                    actions.extend(self.end(ending));
                }
                actions
            }
        }
    }

    /// Asks for a bump when the package can take one: armed, pending or in the mempool, and
    /// with no bump running.
    fn bump(&mut self) -> Option<Action> {
        let bumpable = matches!(self.cpfp, Cpfp::Armed(_))
            && !self.bump_running
            && matches!(
                self.state,
                PackageState::Pending { .. } | PackageState::InMempool
            );
        bumpable.then(|| {
            self.bump_running = true;
            Action::Bump
        })
    }

    /// Asks for a bump when the strategy wants one at the publish.
    fn bump_at_publish(&mut self) -> Option<Action> {
        match &self.cpfp {
            Cpfp::Armed(strategy) if strategy.first_bump == FirstBump::AtPublish => self.bump(),
            Cpfp::Armed(_) | Cpfp::Bare | Cpfp::GaveUp => None,
        }
    }

    /// Ends the package: releases the child of an armed package and reports `ending`.
    fn end(&mut self, ending: Ending) -> Vec<Action> {
        let mut actions = Vec::new();
        if matches!(self.cpfp, Cpfp::Armed(_)) {
            actions.push(Action::Release);
        }
        self.state = PackageState::Ended;
        actions.push(Action::Ended(ending));
        actions
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, Amount, BlockHash, OutPoint};
    use proptest::prelude::*;
    use strata_bridge_primitives::cpfp::ChildSpend;

    use super::*;
    use crate::cpfp::DeadlineClass;

    fn strategy(first_bump: FirstBump) -> CpfpStrategy {
        CpfpStrategy {
            spend: ChildSpend::owned_output(OutPoint::null()),
            parent_fee: Amount::ZERO,
            deadline: DeadlineClass::Deadline,
            first_bump,
        }
    }

    fn armed() -> Cpfp {
        Cpfp::Armed(strategy(FirstBump::AtPublish))
    }

    /// A package in `state` that takes `cpfp`, with no bump running.
    fn pkg(cpfp: Cpfp, state: PackageState) -> Package {
        Package {
            cpfp,
            bump_running: false,
            state,
        }
    }

    /// Opens a package that takes `cpfp`, for a parent read at `status`.
    fn open(cpfp: Option<CpfpStrategy>, status: TxStatus) -> (Package, Vec<Action>) {
        Package::open(cpfp, status)
    }

    /// A package in `state` that takes no bumps.
    fn bare(state: PackageState) -> Package {
        pkg(Cpfp::Bare, state)
    }

    /// Opens a package that takes no bumps, for a parent read at `status`.
    fn open_bare(status: TxStatus) -> (Package, Vec<Action>) {
        open(None, status)
    }

    fn pending_since(cause: PendingCause) -> PackageState {
        PackageState::Pending {
            cause,
            rejection: None,
        }
    }

    fn pending() -> PackageState {
        pending_since(PendingCause::Publish)
    }

    fn evicted() -> PackageState {
        pending_since(PendingCause::Eviction)
    }

    fn mined(height: u64) -> TxStatus {
        TxStatus::Mined {
            blockhash: BlockHash::all_zeros(),
            height,
        }
    }

    fn buried() -> TxStatus {
        TxStatus::Buried {
            blockhash: BlockHash::all_zeros(),
            height: 100,
        }
    }

    fn rejection() -> ClientError {
        ClientError::Other("min relay fee not met".into())
    }

    /// The event of a job with no strategy.
    fn bare_job() -> Event {
        Event::Joined { cpfp: None }
    }

    mod bare_packages {
        use super::*;

        #[test]
        fn opening_an_unknown_parent_sends_it() {
            let (package, actions) = open_bare(TxStatus::Unknown);

            assert_eq!(package.state, pending(), "the parent waits on the send");
            assert_eq!(actions, vec![Action::Broadcast], "the parent goes out bare");
        }

        #[test]
        fn opening_a_parent_that_the_node_holds_reports_it() {
            for status in [TxStatus::Mempool, mined(100)] {
                let (package, actions) = open_bare(status.clone());

                assert_eq!(package.status(), status, "the package follows the parent");
                assert_eq!(
                    actions,
                    vec![Action::Report(status.clone())],
                    "the callers hear the status"
                );
            }
        }

        #[test]
        fn opening_a_buried_parent_ends_the_package() {
            let (package, actions) = open_bare(buried());

            assert_eq!(
                package.state,
                PackageState::Ended,
                "a buried parent needs nothing more"
            );
            assert_eq!(
                actions,
                vec![Action::Report(buried()), Action::Ended(Ending::Buried)],
                "a buried parent reports and ends"
            );
        }

        #[test]
        fn a_job_hears_the_status_of_the_package_it_joins() {
            for (state, status) in [
                (PackageState::InMempool, TxStatus::Mempool),
                (PackageState::Mined(mined(100)), mined(100)),
            ] {
                let joined = bare(state);

                let (package, actions) = joined.clone().step(bare_job());

                assert_eq!(package, joined, "a job changes no state");
                assert_eq!(
                    actions,
                    vec![Action::Report(status)],
                    "the new caller hears the status"
                );
            }
        }

        #[test]
        fn a_job_that_joins_a_pending_package_hears_nothing() {
            for state in [pending(), evicted()] {
                let joined = bare(state);

                let (package, actions) = joined.clone().step(bare_job());

                assert_eq!(package, joined, "a job changes no state");
                assert!(
                    actions.is_empty(),
                    "a pending package has no status to report"
                );
            }
        }

        #[test]
        fn an_accepted_send_enters_the_mempool() {
            let (package, actions) =
                bare(pending()).step(Event::Broadcasted(BroadcastResult::Accepted));

            assert_eq!(
                package.state,
                PackageState::InMempool,
                "the node holds the parent"
            );
            assert_eq!(
                actions,
                vec![Action::Report(TxStatus::Mempool)],
                "the package reports the mempool"
            );
        }

        #[test]
        fn a_send_that_finds_the_parent_in_a_block_follows_it() {
            let (package, actions) =
                bare(pending()).step(Event::Broadcasted(BroadcastResult::Known(mined(101))));

            assert_eq!(
                package.state,
                PackageState::Mined(mined(101)),
                "the package follows the parent into its block"
            );
            assert_eq!(
                actions,
                vec![Action::Report(mined(101))],
                "the package reports the block"
            );
        }

        #[test]
        fn a_rejected_send_ends_the_package() {
            for cause in [PendingCause::Publish, PendingCause::Eviction] {
                let (package, actions) = bare(pending_since(cause))
                    .step(Event::Broadcasted(BroadcastResult::Rejected(rejection())));

                assert_eq!(
                    package.state,
                    PackageState::Ended,
                    "no send can carry the parent"
                );
                assert_eq!(
                    actions,
                    vec![Action::Ended(Ending::Rejected {
                        cause,
                        error: rejection()
                    })],
                    "the cause names the error of the callers"
                );
            }
        }

        #[test]
        fn a_late_send_result_changes_nothing() {
            for state in [PackageState::InMempool, PackageState::Mined(mined(100))] {
                let moved_on = bare(state);

                let (package, actions) = moved_on
                    .clone()
                    .step(Event::Broadcasted(BroadcastResult::Rejected(rejection())));

                assert_eq!(
                    package, moved_on,
                    "the package moved on before the result came back"
                );
                assert!(
                    actions.is_empty(),
                    "the result of an old send changes nothing"
                );
            }
        }

        #[test]
        fn an_eviction_sends_the_parent_again() {
            for state in [PackageState::InMempool, PackageState::Mined(mined(100))] {
                let (package, actions) = bare(state).step(Event::Seen(TxStatus::Unknown));

                assert_eq!(
                    package.state,
                    evicted(),
                    "the package waits on the second send"
                );
                assert_eq!(
                    actions,
                    vec![Action::Broadcast],
                    "the parent goes back bare"
                );
            }
        }

        #[test]
        fn an_unknown_status_leaves_a_pending_package_alone() {
            let waiting = bare(pending());

            let (package, actions) = waiting.clone().step(Event::Seen(TxStatus::Unknown));

            assert_eq!(package, waiting, "a send is already the answer");
            assert!(actions.is_empty(), "nothing goes out twice");
        }

        #[test]
        fn a_parent_follows_its_block_and_a_reorg() {
            let (mined_package, actions) =
                bare(PackageState::InMempool).step(Event::Seen(mined(100)));
            assert_eq!(
                actions,
                vec![Action::Report(mined(100))],
                "the package reports the block"
            );

            let (back, actions) = mined_package.step(Event::Seen(TxStatus::Mempool));
            assert_eq!(
                back.state,
                PackageState::InMempool,
                "a reorg returns the parent to the mempool"
            );
            assert_eq!(
                actions,
                vec![Action::Report(TxStatus::Mempool)],
                "the package reports the mempool"
            );
        }

        #[test]
        fn a_buried_parent_ends_the_package() {
            let (package, actions) = bare(PackageState::InMempool).step(Event::Seen(buried()));

            assert_eq!(
                package.state,
                PackageState::Ended,
                "a buried parent needs nothing more"
            );
            assert_eq!(
                actions,
                vec![Action::Report(buried()), Action::Ended(Ending::Buried)],
                "the package reports the burial and ends"
            );
        }

        #[test]
        fn an_ended_package_ignores_every_event() {
            let ended = bare(PackageState::Ended);

            for event in [
                Event::Seen(TxStatus::Mempool),
                Event::Broadcasted(BroadcastResult::Accepted),
            ] {
                let (package, actions) = ended.clone().step(event);
                assert_eq!(package, ended, "an ended package stays ended");
                assert!(actions.is_empty(), "an ended package emits nothing");
            }
        }
    }

    mod cpfp_packages {
        use super::*;

        #[test]
        fn opening_a_parent_in_the_mempool_bumps_it_at_the_publish_only() {
            let (at_publish, actions) =
                open(Some(strategy(FirstBump::AtPublish)), TxStatus::Mempool);
            assert_eq!(
                at_publish.state,
                PackageState::InMempool,
                "a parent that the node holds is in the mempool"
            );
            assert_eq!(
                actions,
                vec![Action::Report(TxStatus::Mempool), Action::Bump],
                "a presigned parent bumps at once"
            );

            let (_, actions) = open(Some(strategy(FirstBump::AtTrigger)), TxStatus::Mempool);
            assert_eq!(
                actions,
                vec![Action::Report(TxStatus::Mempool)],
                "a parent priced at the market waits for a trigger"
            );
        }

        #[test]
        fn opening_a_mined_parent_takes_no_bump() {
            let (package, actions) = open(Some(strategy(FirstBump::AtPublish)), mined(100));

            assert_eq!(
                package.state,
                PackageState::Mined(mined(100)),
                "the package follows the parent into its block"
            );
            assert_eq!(
                actions,
                vec![Action::Report(mined(100))],
                "a mined parent needs no child"
            );
        }

        #[test]
        fn opening_a_buried_parent_releases_and_ends() {
            let (package, actions) = open(Some(strategy(FirstBump::AtPublish)), buried());

            assert_eq!(
                package.state,
                PackageState::Ended,
                "a buried parent needs nothing more"
            );
            assert_eq!(
                actions,
                vec![
                    Action::Report(buried()),
                    Action::Release,
                    Action::Ended(Ending::Buried)
                ],
                "a buried parent reports, releases and ends"
            );
        }

        #[test]
        fn a_job_with_a_strategy_arms_a_bare_package() {
            let (package, actions) = bare(PackageState::InMempool).step(Event::Joined {
                cpfp: Some(strategy(FirstBump::AtPublish)),
            });

            assert_eq!(package.cpfp, armed(), "the job arms the package");
            assert_eq!(
                actions,
                vec![Action::Report(TxStatus::Mempool), Action::Bump],
                "the caller hears the mempool, and a presigned parent bumps at once"
            );
        }

        #[test]
        fn a_job_does_not_arm_a_package_that_the_bumper_gave_up_on() {
            let gave_up = pkg(Cpfp::GaveUp, PackageState::InMempool);

            let (package, actions) = gave_up.clone().step(Event::Joined {
                cpfp: Some(strategy(FirstBump::AtPublish)),
            });

            assert_eq!(package, gave_up, "every later bump would fail the same way");
            assert_eq!(
                actions,
                vec![Action::Report(TxStatus::Mempool)],
                "the caller hears the mempool, and no bump runs"
            );
        }

        #[test]
        fn a_job_leaves_an_armed_package_as_it_is() {
            let armed = pkg(armed(), PackageState::InMempool);

            for cpfp in [None, Some(strategy(FirstBump::AtTrigger))] {
                let (package, actions) = armed.clone().step(Event::Joined { cpfp });
                assert_eq!(package, armed, "the first strategy stays");
                assert_eq!(
                    actions,
                    vec![Action::Report(TxStatus::Mempool)],
                    "the caller hears the mempool, and a duplicate job runs no bump"
                );
            }
        }

        #[test]
        fn a_job_with_a_strategy_arms_a_mined_parent_with_no_bump() {
            let (package, actions) = bare(PackageState::Mined(mined(100))).step(Event::Joined {
                cpfp: Some(strategy(FirstBump::AtPublish)),
            });

            assert_eq!(package.cpfp, armed(), "the job arms the package");
            assert_eq!(
                actions,
                vec![Action::Report(mined(100))],
                "the caller hears the block, and a mined parent needs no child"
            );
        }

        #[test]
        fn an_accepted_send_bumps_a_presigned_parent() {
            let (package, actions) =
                pkg(armed(), pending()).step(Event::Broadcasted(BroadcastResult::Accepted));

            assert_eq!(
                package.state,
                PackageState::InMempool,
                "the node holds the parent"
            );
            assert_eq!(
                actions,
                vec![Action::Report(TxStatus::Mempool), Action::Bump],
                "the package reports the mempool and bumps a presigned parent"
            );
        }

        #[test]
        fn a_rejected_send_goes_to_the_bumper() {
            let (package, actions) = pkg(armed(), pending())
                .step(Event::Broadcasted(BroadcastResult::Rejected(rejection())));

            assert_eq!(
                package.state,
                PackageState::Pending {
                    cause: PendingCause::Publish,
                    rejection: Some(rejection()),
                },
                "the rejection is kept"
            );
            assert_eq!(
                actions,
                vec![Action::Bump],
                "a package can carry the parent"
            );
        }

        #[test]
        fn a_mined_parent_takes_no_bump_until_it_returns_to_the_mempool() {
            let (mined_package, _) =
                pkg(armed(), PackageState::InMempool).step(Event::Seen(mined(100)));
            let (mined_package, actions) = mined_package.step(Event::Block);
            assert!(actions.is_empty(), "a block does not bump a mined parent");
            let (mined_package, actions) = mined_package.step(Event::Tick);
            assert!(actions.is_empty(), "a tick does not bump a mined parent");

            let (back, _) = mined_package.step(Event::Seen(TxStatus::Mempool));
            let (_, actions) = back.step(Event::Block);
            assert_eq!(
                actions,
                vec![Action::Bump],
                "the bumps resume after the reorg"
            );
        }

        #[test]
        fn a_buried_parent_releases_its_child_and_ends() {
            let (package, actions) =
                pkg(armed(), PackageState::Mined(mined(100))).step(Event::Seen(buried()));

            assert_eq!(
                package.state,
                PackageState::Ended,
                "a buried parent needs nothing more"
            );
            assert_eq!(
                actions,
                vec![
                    Action::Report(buried()),
                    Action::Release,
                    Action::Ended(Ending::Buried)
                ],
                "a buried parent reports, releases and ends"
            );
        }

        #[test]
        fn one_bump_runs_at_a_time() {
            let live = pkg(armed(), PackageState::InMempool);

            let (running, actions) = live.step(Event::Block);
            assert_eq!(
                actions,
                vec![Action::Bump],
                "a block bumps a package with no bump running"
            );
            let (running, actions) = running.step(Event::Tick);
            assert!(actions.is_empty(), "a bump is already running");
            let (done, _) = running.step(Event::Bumped(BumpOutcome::Submitted));
            let (_, actions) = done.step(Event::Block);
            assert_eq!(actions, vec![Action::Bump], "the next trigger bumps again");
        }

        #[test]
        fn a_package_that_reaches_the_network_enters_the_mempool() {
            for outcome in [BumpOutcome::Submitted, BumpOutcome::ParentIsLive] {
                let sent = Package {
                    bump_running: true,
                    ..pkg(armed(), pending())
                };

                let (package, actions) = sent.step(Event::Bumped(outcome));

                assert_eq!(package.state, PackageState::InMempool, "{outcome:?}");
                assert!(!package.bump_running, "{outcome:?}");
                assert_eq!(
                    actions,
                    vec![Action::Report(TxStatus::Mempool)],
                    "the package reports the mempool"
                );
            }
        }

        #[test]
        fn a_bump_with_no_package_changes_no_state() {
            let sent = Package {
                bump_running: true,
                ..pkg(armed(), pending())
            };

            let (package, actions) = sent.clone().step(Event::Bumped(BumpOutcome::NoPackage));

            assert_eq!(package.state, sent.state, "the parent stays where it was");
            assert!(!package.bump_running, "the next trigger can bump again");
            assert!(actions.is_empty(), "the caller keeps waiting");
        }

        #[test]
        fn an_unbumpable_package_releases_its_child_and_continues_bare() {
            let live = Package {
                bump_running: true,
                ..pkg(armed(), PackageState::InMempool)
            };

            let (package, actions) = live.step(Event::Bumped(BumpOutcome::Unbumpable));

            assert_eq!(
                package.cpfp,
                Cpfp::GaveUp,
                "the bumper gave up on the parent"
            );
            assert_eq!(
                package.state,
                PackageState::InMempool,
                "the parent stays in the mempool"
            );
            assert_eq!(actions, vec![Action::Release], "the child's state goes");
        }

        #[test]
        fn an_unbumpable_package_that_the_node_rejected_ends() {
            let rejected = Package {
                bump_running: true,
                ..pkg(
                    armed(),
                    PackageState::Pending {
                        cause: PendingCause::Eviction,
                        rejection: Some(rejection()),
                    },
                )
            };

            let (package, actions) = rejected.step(Event::Bumped(BumpOutcome::Unbumpable));

            assert_eq!(
                package.state,
                PackageState::Ended,
                "no send or bump can carry the parent"
            );
            assert_eq!(
                actions,
                vec![
                    Action::Release,
                    Action::Ended(Ending::Rejected {
                        cause: PendingCause::Eviction,
                        error: rejection(),
                    })
                ],
                "the child is released and the callers hear the rejection"
            );
        }

        #[test]
        fn an_ended_package_ignores_triggers_jobs_and_bumps() {
            let ended = pkg(armed(), PackageState::Ended);

            for event in [
                Event::Block,
                Event::Tick,
                Event::Joined {
                    cpfp: Some(strategy(FirstBump::AtPublish)),
                },
                Event::Bumped(BumpOutcome::Submitted),
            ] {
                let (package, actions) = ended.clone().step(event);
                assert_eq!(package, ended, "an ended package stays ended");
                assert!(actions.is_empty(), "an ended package emits nothing");
            }
        }
    }

    mod invariants {
        use super::*;

        fn arb_status() -> impl Strategy<Value = TxStatus> {
            prop_oneof![
                Just(TxStatus::Unknown),
                Just(TxStatus::Mempool),
                (100u64..110).prop_map(mined),
                Just(buried()),
            ]
        }

        fn arb_strategy(with_strategy: bool) -> BoxedStrategy<Option<CpfpStrategy>> {
            if with_strategy {
                prop_oneof![
                    Just(None),
                    Just(Some(strategy(FirstBump::AtPublish))),
                    Just(Some(strategy(FirstBump::AtTrigger))),
                ]
                .boxed()
            } else {
                Just(None).boxed()
            }
        }

        fn arb_event(with_strategy: bool) -> impl Strategy<Value = Event> {
            prop_oneof![
                arb_strategy(with_strategy).prop_map(|cpfp| Event::Joined { cpfp }),
                arb_status().prop_map(Event::Seen),
                Just(Event::Block),
                Just(Event::Tick),
                arb_broadcast_result().prop_map(Event::Broadcasted),
                prop_oneof![
                    Just(BumpOutcome::Submitted),
                    Just(BumpOutcome::ParentIsLive),
                    Just(BumpOutcome::NoPackage),
                    Just(BumpOutcome::Unbumpable),
                ]
                .prop_map(Event::Bumped),
            ]
        }

        fn arb_broadcast_result() -> impl Strategy<Value = BroadcastResult> {
            prop_oneof![
                Just(BroadcastResult::Accepted),
                (100u64..110).prop_map(|height| BroadcastResult::Known(mined(height))),
                Just(BroadcastResult::Rejected(rejection())),
            ]
        }

        const fn is_armed(package: &Package) -> bool {
            matches!(package.cpfp, Cpfp::Armed(_))
        }

        /// Checks the invariants of one step that concern bumps and children.
        fn check_bumps(
            before: &Package,
            event: &Event,
            after: &Package,
            actions: &[Action],
            releases: &mut usize,
        ) -> Result<(), TestCaseError> {
            let bumps = actions.iter().filter(|a| **a == Action::Bump).count();
            prop_assert!(bumps <= 1, "one bump per step at most");
            if bumps == 1 {
                let was_running = before.bump_running && !matches!(event, Event::Bumped(_));
                prop_assert!(!was_running, "a second bump while one runs");
                prop_assert!(after.bump_running, "a bump marks the package as bumping");
                prop_assert!(is_armed(after), "a bump needs a strategy");
                prop_assert!(
                    matches!(
                        after.state,
                        PackageState::Pending { .. } | PackageState::InMempool
                    ),
                    "only a pending or in-mempool package bumps, got {:?}",
                    after.state
                );
            }

            let released = actions.iter().filter(|a| **a == Action::Release).count();
            if released > 0 {
                prop_assert!(
                    is_armed(before) && (!is_armed(after) || after.state == PackageState::Ended),
                    "a release comes with the loss of the strategy or the end"
                );
            }
            *releases += released;
            prop_assert!(*releases <= 1, "a package releases its child once");

            if matches!(event, Event::Bumped(BumpOutcome::NoPackage)) {
                prop_assert_eq!(
                    &after.state,
                    &before.state,
                    "a fruitless bump changes no state"
                );
            }

            if !is_armed(before) && !matches!(event, Event::Joined { cpfp: Some(_) }) {
                prop_assert_eq!(bumps, 0, "an unarmed package takes no bump");
            }
            Ok(())
        }

        /// Checks the invariants of one step that concern reports and the end.
        fn check_reports(
            before: &Package,
            event: &Event,
            after: &Package,
            actions: &[Action],
            endings: &mut usize,
        ) -> Result<(), TestCaseError> {
            if before.state == PackageState::Ended {
                prop_assert!(actions.is_empty(), "an ended package emits nothing");
            }

            let ended = actions
                .iter()
                .filter(|a| matches!(a, Action::Ended(_)))
                .count();
            *endings += ended;
            prop_assert!(*endings <= 1, "a package ends once");
            prop_assert_eq!(
                ended == 1,
                before.state != PackageState::Ended && after.state == PackageState::Ended,
                "an ending comes with the move into the ended state"
            );

            for action in actions {
                if let Action::Report(status) = action {
                    prop_assert_ne!(status, &TxStatus::Unknown, "a report names a status");
                    prop_assert!(
                        after.state == PackageState::Ended || *status == after.status(),
                        "a report matches the new state"
                    );
                }
            }

            let status = after.status();
            let joined = matches!(event, Event::Joined { .. });
            if joined && status != TxStatus::Unknown {
                prop_assert!(
                    actions.contains(&Action::Report(status)),
                    "a job hears the status of the package it joins"
                );
            }
            Ok(())
        }

        proptest! {
            #[test]
            fn every_step_keeps_the_invariants(
                cpfp in arb_strategy(true),
                status in arb_status(),
                events in proptest::collection::vec(arb_event(true), 0..40),
            ) {
                let (mut package, actions) = open(cpfp, status);
                let mut releases = actions.iter().filter(|a| **a == Action::Release).count();
                let mut endings = actions.iter().filter(|a| matches!(a, Action::Ended(_))).count();
                prop_assert!(releases <= 1, "the opening releases the child once at most");

                for event in events {
                    let before = package.clone();
                    let (after, actions) = before.clone().step(event.clone());
                    check_bumps(&before, &event, &after, &actions, &mut releases)?;
                    check_reports(&before, &event, &after, &actions, &mut endings)?;
                    package = after;
                }
            }

            #[test]
            fn a_bare_package_never_bumps(
                status in arb_status(),
                events in proptest::collection::vec(arb_event(false), 0..40),
            ) {
                let (mut package, actions) = open_bare(status);
                prop_assert!(!actions.contains(&Action::Bump), "a bare package takes no bump");
                for event in events {
                    let (after, actions) = package.step(event);
                    prop_assert!(!actions.contains(&Action::Bump), "a bare package takes no bump");
                    prop_assert!(
                        !actions.contains(&Action::Release),
                        "a bare package has no child to release"
                    );
                    package = after;
                }
            }
        }
    }
}
