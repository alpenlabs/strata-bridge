//! The loop that owns every package, turns what it observes into events, and runs the actions.
//!
//! The tracker is the only code that changes a package. It hands sends to the [`Broadcaster`]
//! and bumps to the [`Bumper`], and their results come back as events like any observation of
//! the chain. It also keeps the callers of each package, which the state machine knows nothing
//! of: it answers them when the package reports a status or ends.

use std::{collections::HashMap, sync::Arc, time::Duration};

use bitcoin::{OutPoint, Transaction, Txid};
use bitcoind_async_client::error::ClientError;
use futures::{
    channel::oneshot,
    stream::{abortable, AbortHandle, Abortable, SelectAll},
    StreamExt,
};
use strata_bridge_primitives::subscription::Subscription;
use tokio::{select, sync::mpsc::UnboundedReceiver, time::Interval};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::warn;

use super::{
    broadcaster::Broadcaster,
    bumper::Bumper,
    errors::DriveErr,
    node::ChainAccess,
    package::{Action, Ending, Event, Package, PackageId, PendingCause},
};
use crate::{
    cpfp::{BumpOutcome, CpfpBumper, CpfpStrategy, DeadlineClass},
    event::{BlockEvent, BlockStatus, TxEvent, TxStatus},
};

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
    /// The strategy that bumps the transaction, when the caller wants CPFP.
    pub(super) cpfp: Option<CpfpStrategy>,
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
pub(super) struct Tracker<B: CpfpBumper> {
    chain: Arc<dyn ChainAccess>,
    bury_depth: u64,
    entries: HashMap<PackageId, Entry>,
    /// The live package of each txid.
    by_txid: HashMap<Txid, PackageId>,
    next_id: u64,
    subscriptions: SelectAll<Abortable<Subscription<TxEvent>>>,
    broadcaster: Broadcaster,
    /// `None` for a driver that sends bare transactions only.
    bumper: Option<Bumper<B>>,
}

impl<B: CpfpBumper> Tracker<B> {
    pub(super) fn new(
        chain: Arc<dyn ChainAccess>,
        bury_depth: u64,
        bumper: Option<Arc<B>>,
    ) -> Self {
        Self {
            broadcaster: Broadcaster::new(chain.clone()),
            chain,
            bury_depth,
            entries: HashMap::new(),
            by_txid: HashMap::new(),
            next_id: 0,
            subscriptions: SelectAll::new(),
            bumper: bumper.map(Bumper::new),
        }
    }

    /// The driver loop. `bump_interval` is `None` for a driver with no bumper.
    pub(super) async fn run(
        mut self,
        jobs: UnboundedReceiver<Job>,
        mut blocks: Subscription<BlockEvent>,
        bump_interval: Option<Duration>,
    ) {
        let mut jobs = UnboundedReceiverStream::new(jobs);
        let mut ticks = bump_interval.map(tokio::time::interval);
        if let Some(ticks) = ticks.as_mut() {
            // The first tick of an interval fires at once.
            ticks.tick().await;
        }
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
                () = next_tick(ticks.as_mut()) => self.apply_all(&Event::Tick),
                Some((id, result)) = self.broadcaster.next_result() => {
                    self.apply(id, Event::Broadcasted(result));
                }
                Some((id, outcome)) = next_outcome(self.bumper.as_mut()) => {
                    self.apply(id, Event::Bumped(outcome));
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
        let Job { tx, caller, cpfp } = job;
        let cpfp = cpfp.filter(|_| self.bumper.is_some());
        let txid = tx.compute_txid();

        if let Some(&id) = self.by_txid.get(&txid) {
            let status = read_status(self.chain.as_ref(), txid).await;
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.callers.push(caller);
            }
            if let Some(status) = status {
                self.apply(id, Event::Seen(status));
            }
            self.apply(id, Event::Joined { cpfp });
            return;
        }

        let (subscription, abort) = abortable(self.chain.subscribe(&tx).await);
        self.subscriptions.push(subscription);
        let status = read_status(self.chain.as_ref(), txid)
            .await
            .unwrap_or(TxStatus::Unknown);
        let id = PackageId(self.next_id);
        self.next_id += 1;
        let (package, actions) = Package::open(cpfp, self.bury_depth, status);
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

    /// Applies one block to every package: a reorg first, then the read of each package, then
    /// the block itself. Every read lands before the block, so a parent that this block mined
    /// is never bumped by it.
    async fn on_block(&mut self, status: BlockStatus) {
        // A block reaches burial in the same step that connects another block, so a buried block
        // brings no change of its own.
        if status == BlockStatus::Buried {
            return;
        }
        if status == BlockStatus::Uncled {
            self.apply_all(&Event::Reorged);
        }
        for id in self.ids_by_deadline() {
            let Some(entry) = self.entries.get(&id) else {
                continue;
            };
            let txid = entry.tx.compute_txid();
            // A bare package takes no conflict, so it reads no inputs.
            let inputs: Vec<OutPoint> = match entry.package.strategy() {
                Some(_) => entry.tx.input.iter().map(|i| i.previous_output).collect(),
                None => Vec::new(),
            };
            match read(self.chain.as_ref(), txid, &inputs).await {
                Ok((input_spent, status, tip)) => self.apply(
                    id,
                    Event::Read {
                        input_spent,
                        status,
                        tip,
                    },
                ),
                Err(err) => {
                    warn!(%txid, %err, "could not read the transaction; the next block retries")
                }
            }
        }
        self.apply_all(&Event::Block);
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

    /// Applies `event` to every package, deadline packages first, so that their bumps queue
    /// first.
    fn apply_all(&mut self, event: &Event) {
        for id in self.ids_by_deadline() {
            self.apply(id, event.clone());
        }
    }

    fn run_actions(&mut self, id: PackageId, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Broadcast => {
                    if let Some(entry) = self.entries.get(&id) {
                        self.broadcaster.request(id, entry.tx.clone());
                    }
                }
                Action::Bump => {
                    let (Some(entry), Some(bumper)) = (self.entries.get(&id), self.bumper.as_mut())
                    else {
                        continue;
                    };
                    if let Some(strategy) = entry.package.strategy() {
                        bumper.request(id, entry.tx.clone(), strategy.clone());
                    }
                }
                Action::Release => {
                    if let Some(bumper) = self.bumper.as_mut() {
                        bumper.release(id);
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
            Ending::ConflictBuried => DriveErr::ConflictBuried,
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

    /// The ids of every package, deadline packages first, then in the order they opened.
    fn ids_by_deadline(&self) -> Vec<PackageId> {
        let mut ids: Vec<_> = self
            .entries
            .iter()
            .map(|(id, entry)| {
                let no_deadline = entry
                    .package
                    .strategy()
                    .is_none_or(|strategy| strategy.deadline != DeadlineClass::Deadline);
                (no_deadline, *id)
            })
            .collect();
        ids.sort();
        ids.into_iter().map(|(_, id)| id).collect()
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

/// Reads what [`Event::Read`] carries, in the order that it states: whether a confirmed
/// transaction spends one of `inputs`, the status of `txid`, and the tip.
async fn read(
    chain: &dyn ChainAccess,
    txid: Txid,
    inputs: &[OutPoint],
) -> Result<(bool, TxStatus, u64), ClientError> {
    let mut input_spent = false;
    for outpoint in inputs {
        if chain.is_spent_on_chain(*outpoint).await? {
            input_spent = true;
            break;
        }
    }
    let status = chain.fetch_status(txid).await?;
    let tip = chain.tip_height().await?;
    Ok((input_spent, status, tip))
}

/// Waits for the next tick of `ticks`, or forever when there are none.
async fn next_tick(ticks: Option<&mut Interval>) {
    match ticks {
        Some(ticks) => {
            ticks.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// Waits for the next outcome of `bumper`, or forever when there is no bumper.
async fn next_outcome<B: CpfpBumper>(
    bumper: Option<&mut Bumper<B>>,
) -> Option<(PackageId, BumpOutcome)> {
    match bumper {
        Some(bumper) => bumper.next_outcome().await,
        None => std::future::pending().await,
    }
}
