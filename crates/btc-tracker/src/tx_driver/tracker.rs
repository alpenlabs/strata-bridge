//! The loop that owns every package, turns what it observes into events, and runs the actions.
//!
//! The tracker is the only code that changes a package. It hands sends to the [`Broadcaster`],
//! and their results come back as events like any observation of the chain. It also keeps the
//! callers of each package, which the state machine knows nothing of: it answers them when the
//! package reports a status or ends.

use std::{collections::HashMap, sync::Arc};

use bitcoin::{Transaction, Txid};
use futures::{
    channel::oneshot,
    stream::{abortable, AbortHandle, Abortable, SelectAll},
    StreamExt,
};
use strata_bridge_primitives::subscription::Subscription;
use tokio::{select, sync::mpsc::UnboundedReceiver};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::warn;

use super::{
    broadcaster::Broadcaster,
    errors::DriveErr,
    node::ChainAccess,
    package::{Action, Ending, Event, Package, PackageId, PendingCause},
};
use crate::event::{BlockEvent, BlockStatus, TxEvent, TxStatus};

/// The channel that answers one caller.
pub(super) type Responder = oneshot::Sender<Result<(), DriveErr>>;

/// One caller that waits for a status condition.
pub(super) struct Caller {
    /// The condition upon which the caller hears `Ok`.
    pub(super) condition: Box<dyn Fn(&TxStatus) -> bool + Send>,
    /// The channel that answers the caller.
    pub(super) respond_on: Responder,
}

/// One request to drive a transaction.
pub(super) struct Job {
    pub(super) tx: Transaction,
    pub(super) caller: Caller,
}

/// What the tracker keeps for one package besides its state machine.
struct Entry {
    package: Package,
    tx: Transaction,
    callers: Vec<Caller>,
    /// Ends the ZMQ subscription of the transaction.
    ///
    /// `SelectAll` has no removal method, so each subscription enters it through
    /// [`futures::stream::abortable`]. An abort ends that stream, and `SelectAll` drops it on the
    /// next poll.
    subscription: AbortHandle,
}

/// Owns every package, its transaction and its callers.
pub(super) struct Tracker {
    chain: Arc<dyn ChainAccess>,
    entries: HashMap<PackageId, Entry>,
    /// The live package of each txid.
    by_txid: HashMap<Txid, PackageId>,
    next_id: u64,
    subscriptions: SelectAll<Abortable<Subscription<TxEvent>>>,
    broadcaster: Broadcaster,
}

impl Tracker {
    pub(super) fn new(chain: Arc<dyn ChainAccess>) -> Self {
        Self {
            broadcaster: Broadcaster::new(chain.clone()),
            chain,
            entries: HashMap::new(),
            by_txid: HashMap::new(),
            next_id: 0,
            subscriptions: SelectAll::new(),
        }
    }

    /// The driver loop.
    pub(super) async fn run(
        mut self,
        jobs: UnboundedReceiver<Job>,
        mut blocks: Subscription<BlockEvent>,
    ) {
        let mut jobs = UnboundedReceiverStream::new(jobs);
        loop {
            select! {
                Some(job) = jobs.next() => self.on_job(job).await,
                Some(event) = self.subscriptions.next() => {
                    let txid = event.rawtx.compute_txid();
                    if let Some(&id) = self.by_txid.get(&txid) {
                        self.apply(id, Event::Seen(event.status));
                    }
                }
                Some(block) = blocks.next() => self.on_block(block.status).await,
                Some((id, result)) = self.broadcaster.next_result() => {
                    self.apply(id, Event::Broadcasted(result));
                }
            }
        }
    }

    /// Joins a job to the package of its txid, or opens a package for it.
    ///
    /// Each job reads the status, so a retry of a caller sees what ZMQ missed. A job that joins
    /// a package applies its read before it joins, so its caller hears the fresh status. A new
    /// package opens its subscription before the read, so no event falls between the two. A
    /// read that fails counts as `Unknown` for a new package, and the node decides at the send.
    async fn on_job(&mut self, job: Job) {
        let Job { tx, caller } = job;
        let txid = tx.compute_txid();

        if let Some(&id) = self.by_txid.get(&txid) {
            let status = read_status(self.chain.as_ref(), txid).await;
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.callers.push(caller);
            }
            if let Some(status) = status {
                self.apply(id, Event::Seen(status));
            }
            self.apply(id, Event::Joined);
            return;
        }

        let (subscription, abort) = abortable(self.chain.subscribe(&tx).await);
        self.subscriptions.push(subscription);
        let status = read_status(self.chain.as_ref(), txid)
            .await
            .unwrap_or(TxStatus::Unknown);
        let id = PackageId(self.next_id);
        self.next_id += 1;
        let (package, actions) = Package::open(status);
        self.entries.insert(
            id,
            Entry {
                package,
                tx,
                callers: vec![caller],
                subscription: abort,
            },
        );
        self.by_txid.insert(txid, id);
        self.run_actions(id, actions);
    }

    /// Reads every package on a block, so that a status that ZMQ missed still reaches it.
    async fn on_block(&mut self, status: BlockStatus) {
        // A block reaches burial in the same step that connects another block, so a buried block
        // brings no change of its own.
        if status == BlockStatus::Buried {
            return;
        }
        let ids: Vec<_> = self.entries.keys().copied().collect();
        for id in ids {
            let Some(entry) = self.entries.get(&id) else {
                continue;
            };
            let txid = entry.tx.compute_txid();
            if let Some(status) = read_status(self.chain.as_ref(), txid).await {
                self.apply(id, Event::Seen(status));
            }
        }
    }

    /// Steps the package `id` and runs its actions. An event for a package that ended does
    /// nothing.
    fn apply(&mut self, id: PackageId, event: Event) {
        let Some(mut entry) = self.entries.remove(&id) else {
            return;
        };
        let (package, actions) = entry.package.step(event);
        entry.package = package;
        self.entries.insert(id, entry);
        self.run_actions(id, actions);
    }

    fn run_actions(&mut self, id: PackageId, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Broadcast => {
                    if let Some(entry) = self.entries.get(&id) {
                        self.broadcaster.request(id, entry.tx.clone());
                    }
                }
                Action::Report(status) => self.report(id, &status),
                Action::Ended(ending) => self.end(id, ending),
            }
        }
    }

    /// Reports `status` to the callers of `id`. Each caller whose condition `status` meets is
    /// answered `Ok`, and the others keep waiting.
    fn report(&mut self, id: PackageId, status: &TxStatus) {
        let Some(entry) = self.entries.get_mut(&id) else {
            return;
        };
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut entry.callers)
            .into_iter()
            .partition(|caller| (caller.condition)(status));
        entry.callers = waiting;
        for caller in ready {
            let _ = caller.respond_on.send(Ok(()));
        }
    }

    /// Drops the package `id`, ends its subscription, and answers every caller that still
    /// waits.
    fn end(&mut self, id: PackageId, ending: Ending) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        let txid = entry.tx.compute_txid();
        if self.by_txid.get(&txid) == Some(&id) {
            self.by_txid.remove(&txid);
        }
        entry.subscription.abort();
        let error = match ending {
            Ending::Buried => DriveErr::ConditionUnmet,
            Ending::Rejected {
                cause: PendingCause::Publish,
                error,
            } => DriveErr::PublishFailed(error),
            Ending::Rejected {
                cause: PendingCause::Eviction,
                error,
            } => DriveErr::Evicted {
                txid,
                source: error,
            },
        };
        for caller in entry.callers {
            let _ = caller.respond_on.send(Err(error.clone()));
        }
    }
}

/// Reads the status of `txid`. A failed read is logged and reads as `None`.
async fn read_status(chain: &dyn ChainAccess, txid: Txid) -> Option<TxStatus> {
    chain
        .fetch_status(txid)
        .await
        .inspect_err(|err| warn!(%txid, %err, "could not read the transaction"))
        .ok()
}
