//! The lifecycle of one package: a transaction that the driver sends and follows to burial.
//!
//! [`Package::step`] is a pure transition from one [`Event`] to the next package and the
//! [`Action`]s that the tracker runs. The machine knows nothing of the callers that wait on the
//! parent: it reports its status when the status changes or a job joins, and it reports its end.
//! The tracker answers the callers.

use bitcoind_async_client::error::ClientError;

use crate::event::TxStatus;

/// Identifies one package for its whole life. A new job for a txid whose package ended opens a
/// package with a new id, so a late result for the old one cannot touch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct PackageId(pub(super) u64);

/// One package and where the driver last saw it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Package {
    state: PackageState,
}

/// Where the driver last saw the parent.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum PackageState {
    /// In no mempool and in no block since `cause`.
    Pending {
        cause: PendingCause,
    },
    InMempool,
    /// In a block, not yet buried.
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
    /// A job for this parent joined. Its caller hears the status of the package.
    Joined,
    /// A status of the parent from ZMQ, from a job, or from the read on each block. `Unknown`
    /// means that it left the mempool.
    Seen(TxStatus),
    /// A bare send that this package asked for finished.
    Broadcasted(BroadcastResult),
}

/// One output of [`Package::step`].
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Action {
    /// Send the parent bare.
    Broadcast,
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
    /// The node rejected the parent.
    Rejected {
        cause: PendingCause,
        error: ClientError,
    },
}

impl Package {
    /// Opens a package for a parent that a job read at `status`. A failed read counts as
    /// `Unknown`, and the node decides at the send.
    pub(super) fn open(status: TxStatus) -> (Self, Vec<Action>) {
        let mut package = Self {
            state: PackageState::Pending {
                cause: PendingCause::Publish,
            },
        };
        let actions = match status {
            TxStatus::Unknown => vec![Action::Broadcast],
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
            Event::Joined => self.report().into_iter().collect(),
            Event::Seen(status) => self.observe(status),
            Event::Broadcasted(result) => self.broadcasted(result),
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

    const fn evicted() -> PackageState {
        PackageState::Pending {
            cause: PendingCause::Eviction,
        }
    }

    /// Follows a status of the parent. A parent that left the mempool or its block goes back
    /// bare, unless the package already waits on a send.
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

    /// Applies the result of a bare send. A result that arrives after the package moved on
    /// changes nothing.
    fn broadcasted(&mut self, result: BroadcastResult) -> Vec<Action> {
        let PackageState::Pending { cause } = self.state else {
            return Vec::new();
        };
        match result {
            BroadcastResult::Accepted => self.observe(TxStatus::Mempool),
            BroadcastResult::Known(status) => self.observe(status),
            BroadcastResult::Rejected(error) => self.end(Ending::Rejected { cause, error }),
        }
    }

    /// Ends the package and reports `ending`.
    fn end(&mut self, ending: Ending) -> Vec<Action> {
        self.state = PackageState::Ended;
        vec![Action::Ended(ending)]
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, BlockHash};
    use proptest::prelude::*;

    use super::*;

    /// A package in `state`.
    fn bare(state: PackageState) -> Package {
        Package { state }
    }

    /// Opens a package for a parent read at `status`.
    fn open_bare(status: TxStatus) -> (Package, Vec<Action>) {
        Package::open(status)
    }

    fn pending_since(cause: PendingCause) -> PackageState {
        PackageState::Pending { cause }
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
        Event::Joined
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

        fn arb_event() -> impl Strategy<Value = Event> {
            prop_oneof![
                Just(Event::Joined),
                arb_status().prop_map(Event::Seen),
                arb_broadcast_result().prop_map(Event::Broadcasted),
            ]
        }

        fn arb_broadcast_result() -> impl Strategy<Value = BroadcastResult> {
            prop_oneof![
                Just(BroadcastResult::Accepted),
                (100u64..110).prop_map(|height| BroadcastResult::Known(mined(height))),
                Just(BroadcastResult::Rejected(rejection())),
            ]
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
            let joined = matches!(event, Event::Joined);
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
                status in arb_status(),
                events in proptest::collection::vec(arb_event(), 0..40),
            ) {
                let (mut package, actions) = open_bare(status);
                let mut endings = actions.iter().filter(|a| matches!(a, Action::Ended(_))).count();

                for event in events {
                    let before = package.clone();
                    let (after, actions) = before.clone().step(event.clone());
                    check_reports(&before, &event, &after, &actions, &mut endings)?;
                    package = after;
                }
            }
        }
    }
}
