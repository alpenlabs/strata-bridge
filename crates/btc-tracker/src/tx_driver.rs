//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use bitcoin::{Amount, FeeRate, Transaction, Txid};
use bitcoind_async_client::{
    error::ClientError,
    traits::{Broadcaster, Reader},
    types::BroadcastOptions,
    Client as BitcoinClient,
};
use futures::{
    channel::oneshot,
    stream::{abortable, AbortHandle, Abortable, SelectAll},
    FutureExt, StreamExt,
};
use strata_bridge_primitives::subscription::Subscription;
use thiserror::Error;
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        Mutex,
    },
    task::JoinHandle,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, info, warn};

use crate::{
    client::{BtcNotifyClient, Connected},
    cpfp::{
        self, BumpOutcome, BumpReason, CpfpContext, CpfpDisabled, CpfpFeeSource, CpfpHandle,
        CpfpMempool, CpfpStrategy, CpfpWallet,
    },
    event::{TxEvent, TxStatus},
};

/// Error type for the TxDriver.
#[derive(Debug, Error)]
pub enum DriveErr {
    /// Indicates that the TxDriver has been dropped and no more events should be expected.
    #[error("tx driver has been aborted, no more events should be expected")]
    DriverAborted,

    /// Indicates that the transaction could not be published.
    #[error("could not publish transaction: {0}")]
    PublishFailed(ClientError),

    /// The transaction reached burial before the caller's condition was true. The driver
    /// stops tracking a transaction at burial, so the condition can never become true after
    /// this point.
    #[error("transaction was buried before the wait condition was met")]
    ConditionUnmet,
}

/// This is the minimal description of a request to drive a transaction.
struct TxDriveJob {
    /// The actual transaction to publish
    tx: Transaction,

    /// The condition upon which we will notify the drive caller
    condition: Box<dyn Fn(&TxStatus) -> bool + Send>,

    /// The channel that we should publish on when the job is done.
    respond_on: oneshot::Sender<Result<(), DriveErr>>,

    /// Optional CPFP strategy. When present, the driver builds (and replaces on each new
    /// block / mempool eviction) a CPFP child to lift the package fee rate toward the fee
    /// source's target. Disabled for non-CPFP txs.
    cpfp: Option<CpfpStrategy>,
}

impl TxDriveJob {
    /// Returns the condition upon which the caller needs to be notified.
    fn condition(&self) -> &(dyn Fn(&TxStatus) -> bool + Send) {
        &self.condition
    }
}

type TxSubscriberSet = Vec<(
    Box<dyn Fn(&TxStatus) -> bool + Send>,
    oneshot::Sender<Result<(), DriveErr>>,
)>;

fn broadcast_options(tx: &Transaction) -> Option<BroadcastOptions> {
    let max_burn_amount = tx
        .output
        .iter()
        .filter(|output| output.value > Amount::ZERO && output.script_pubkey.is_op_return())
        .map(|output| output.value)
        .max()?;

    Some(BroadcastOptions {
        max_burn_amount: Some(max_burn_amount),
        ..Default::default()
    })
}

/// Sentinel bump-tick interval used by [`TxDriver::new`] (no-CPFP path). The bump arm
/// inside the driver's select loop fires on this cadence but immediately short-circuits
/// when `cpfp_ctx` is `None`, so a long interval keeps the no-CPFP path effectively idle.
const NO_CPFP_BUMP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Default bridge protocol-floor fee rate used by [`TxDriver::new`] (no-CPFP path). MUST
/// equal `strata_bridge_tx_graph::fee::FEE_RATE_SAT_PER_VB` — but `btc-tracker` cannot
/// depend on `tx-graph` (layering), so the value is duplicated here with a grep-anchorable
/// const name. If `FEE_RATE_SAT_PER_VB` ever changes, search for `DEFAULT_PROTOCOL_FLOOR`
/// to find and update this. Production (CPFP-enabled) calls [`TxDriver::with_cpfp`] and
/// passes `fee::FEE_RATE` directly, so this only affects the legacy no-CPFP constructor.
const DEFAULT_PROTOCOL_FLOOR: FeeRate = FeeRate::from_sat_per_vb_unchecked(2);

/// How far the driver has seen a transaction advance.
///
/// The stage and the presence of a record together give three states: bumping, waiting for
/// burial, and gone. The stage field holds the first two, and each event arm sets it
/// directly. The third is the absence of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Not in a block. CPFP bumps run.
    Unconfirmed,
    /// In a block, not yet buried. CPFP bumps stop, because a confirmed parent needs no
    /// child. The record stays: a reorg returns the transaction to [`Self::Unconfirmed`] and
    /// the bumps must resume then. A removal at this point makes the parent unbumpable for
    /// the rest of the wait, and a floor-rate parent that no mempool accepts never confirms.
    Mined,
}

/// Marks one parent as having a bump in flight, and clears the mark when it drops.
///
/// The bump task owns the guard, so the mark clears when the task ends by any route,
/// including a panic. A flag that a task sets and clears by hand stays set after a panic, and
/// no later bump for that parent can start.
#[derive(Debug)]
struct BumpGuard(Arc<AtomicBool>);

impl BumpGuard {
    /// The mark that this guard holds. Two records for one txid hold different marks, so
    /// pointer identity tells a bump whether the record it started on is still the one there.
    const fn mark(&self) -> &Arc<AtomicBool> {
        &self.0
    }
}

impl Drop for BumpGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// CPFP state for one parent.
#[derive(Debug)]
struct CpfpState {
    strategy: CpfpStrategy,
    handle: CpfpHandle,
    /// Whether a bump for this parent is in flight.
    ///
    /// One bump per parent at a time. Two concurrent bumps take a snapshot of the same
    /// handle, and the later write-back drops the lease of the live child. The mark is per
    /// parent, so a slow bump for one parent does not stop the bumps for every other parent,
    /// and no trigger has to fall back to a degraded path.
    bumping: Arc<AtomicBool>,
}

impl CpfpState {
    /// A fresh state for `strategy`, with no child built yet.
    fn new(strategy: CpfpStrategy) -> Self {
        Self {
            strategy,
            handle: CpfpHandle::default(),
            bumping: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Marks a bump as in flight and returns the guard that clears the mark. Returns `None`
    /// when a bump is already running for this parent.
    fn start_bump(&self) -> Option<BumpGuard> {
        self.bumping
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| BumpGuard(Arc::clone(&self.bumping)))
    }

    /// Whether a bump for this parent is in flight.
    fn is_bumping(&self) -> bool {
        self.bumping.load(Ordering::Acquire)
    }
}

/// Everything the driver tracks for one transaction that it drives.
///
/// The listeners, the ZMQ subscription, and the CPFP state share one lifetime, so they share
/// one record. A single removal ends the subscription and drops the lease of the last CPFP
/// child together, and it answers each listener that is still waiting.
///
/// Separate structures keyed on the same txid give each event arm three things to keep
/// consistent. Any arm that updates two of the three leaks the third.
struct ParentRecord {
    /// The transaction. A bump uses it to rebuild the child.
    tx: Transaction,
    /// Callers that wait for a status condition.
    listeners: TxSubscriberSet,
    stage: Stage,
    /// `None` when the caller asked for no CPFP.
    cpfp: Option<CpfpState>,
    /// Ends the ZMQ subscription of this transaction.
    ///
    /// [`SelectAll`] has no removal method, so each subscription enters it through
    /// [`futures::stream::abortable`]. An abort ends that stream, and `SelectAll` drops it on
    /// the next poll. Without a way to end it, each driven transaction holds one entry in
    /// `SelectAll` for the lifetime of the process.
    ///
    /// The client keeps its own sender and filter until an event matches the predicate again
    /// and the send fails. A buried transaction produces no further match, so that side is
    /// not freed here.
    subscription: AbortHandle,
}

impl ParentRecord {
    /// Answers every listener whose condition `status` satisfies, and keeps the rest.
    fn notify(&mut self, status: &TxStatus) {
        let waiting = std::mem::take(&mut self.listeners);
        self.listeners = waiting
            .into_iter()
            .filter_map(|(condition, respond_on)| {
                if condition(status) {
                    let _ = respond_on.send(Ok(()));
                    None
                } else {
                    Some((condition, respond_on))
                }
            })
            .collect();
    }

    /// Whether a bump can run for this parent now.
    fn is_bumpable(&self) -> bool {
        self.stage == Stage::Unconfirmed
            && self.cpfp.as_ref().is_some_and(|cpfp| !cpfp.is_bumping())
    }
}

/// The transactions that the driver drives, keyed on txid.
///
/// `Arc<Mutex>` so a spawned bump task can take a brief lock without blocking the driver loop
/// through a wallet build, a signing round trip, and a `submitpackage` call.
type Parents = Arc<Mutex<HashMap<Txid, ParentRecord>>>;

/// Whether `record` is the one whose CPFP state holds `mark`.
fn holds_mark(record: Option<&ParentRecord>, mark: &Arc<AtomicBool>) -> bool {
    record
        .and_then(|record| record.cpfp.as_ref())
        .is_some_and(|cpfp| Arc::ptr_eq(&cpfp.bumping, mark))
}

/// Bare (non-package) resubmission of an evicted transaction. This is the path for a parent
/// without CPFP, and the fallback when a bump submits no package.
async fn resubmit_bare(rpc_client: &BitcoinClient, rawtx: &Transaction, evicted_txid: Txid) {
    let options = broadcast_options(rawtx);
    match rpc_client.send_raw_transaction(rawtx, options).await {
        Ok(txid) => {
            info!(%txid, "resubmitted transaction successfully");
        }
        Err(err) => {
            // `warn`, not `error`: a floor-rate parent evicted under fee pressure is
            // rejected here on each attempt by design, and the CPFP path (next block or
            // tick) is what actually recovers it. An error level buries real faults.
            warn!(%evicted_txid, %err, "could not resubmit transaction");
            // TODO: <https://alpenlabs.atlassian.net/browse/STR-2690>
            // Analyze the reported error and classify the submission
            // failure mode.
            //
            // 1. It failed because one or more of the inputs is double
            // spent.
            // 2. It failed because the fee didn't exceed the purge
            // rate.
            // 3. If failed because the transaction has already
            // re-entered the mempool automatically upon reorg.
        }
    }
}

/// Runs one `perform_bump` for `parent_txid` and writes the updated handle back.
///
/// Returns whether a `[parent, child]` package reached the mempool. Returns `false` when the
/// record is gone, or when its stage is no longer `Unconfirmed`. An event arm settles the
/// parent that way between the caller's look-up and this one.
///
/// The handle is written back **even when the bump fails**. `perform_bump` takes the lease on
/// the new child's funding inputs before the steps that can fail. The write-back keeps that
/// lease for the next attempt.
async fn bump_parent<W, F, P>(
    ctx: &CpfpContext<W, F, P>,
    parents: &Parents,
    parent_txid: Txid,
    mark: &Arc<AtomicBool>,
    bridge_protocol_floor: FeeRate,
    reason: cpfp::BumpReason,
) -> BumpOutcome
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    // Snapshot under a brief lock. The slow bump runs without the parents mutex held.
    let snapshot = parents.lock().await.get(&parent_txid).and_then(|record| {
        if record.stage != Stage::Unconfirmed {
            return None;
        }
        let cpfp = record.cpfp.as_ref()?;
        Some((
            record.tx.clone(),
            cpfp.strategy.clone(),
            cpfp.handle.clone(),
        ))
    });
    let Some((parent, strategy, mut handle)) = snapshot else {
        return BumpOutcome::NoChildNeeded;
    };
    let result = cpfp::perform_bump(
        ctx,
        &parent,
        strategy,
        &mut handle,
        bridge_protocol_floor,
        reason,
    )
    .await;

    // Write the updated handle back while the record is still bumpable. A record that has
    // gone or reached `Mined` means an event arm settled this parent during the bump.
    //
    // Neither case needs a release call. The local handle drops at the end of this function.
    // When this bump built a child, the local handle owns the only clone of that lease and
    // the drop frees the inputs. When the write-back is skipped, the removal or the `Mined`
    // arm already dropped the record's clone, so the drop frees those inputs as well. That is
    // correct for a parent that is gone or mined.
    let mut guard = parents.lock().await;
    if holds_mark(guard.get(&parent_txid), mark) {
        if let Some(record) = guard.get_mut(&parent_txid) {
            if record.stage == Stage::Unconfirmed {
                if let Some(cpfp) = record.cpfp.as_mut() {
                    cpfp.handle = handle;
                }
            }
        }
    }
    drop(guard);

    match result {
        Ok(outcome) => {
            if outcome == BumpOutcome::Submitted {
                debug!(%parent_txid, ?reason, "CPFP bump submitted");
            }
            outcome
        }
        Err(e) if e.is_unbumpable() => {
            // `warn!`, not `error!`: a re-driven job re-arms the bumps for this parent, so a
            // persistent Unbumpable parent would log at `error!` once per duty retry. The
            // bare paths keep carrying the parent in the meantime.
            warn!(
                %parent_txid,
                error = %e,
                ?reason,
                "parent cannot carry a CPFP child; stopping the bumps for it"
            );
            BumpOutcome::Unbumpable
        }
        Err(e) if e.is_replacement_contention_for(&parent_txid) => {
            // The parent itself lost a replacement race: a transaction that conflicts with
            // the parent is in the mempool, and the parent is not. Nothing more is known.
            debug!(%parent_txid, ?reason, "parent lost a replacement race to a conflicting transaction");
            BumpOutcome::NoChildNeeded
        }
        Err(e) if e.is_replacement_contention() => {
            // The child lost the race. The usual incumbent is another watchtower's child on
            // a shared anchor, or this operator's own prior child under BIP-125 rule 4.
            // Both spend an output of this parent, so the parent is in a mempool. Expected
            // on every trigger until the parent confirms.
            debug!(%parent_txid, ?reason, "CPFP bump lost the race for a shared anchor");
            BumpOutcome::ParentIsLive
        }
        Err(e) => {
            warn!(%parent_txid, error = %e, ?reason, "CPFP bump failed; will retry on next trigger");
            BumpOutcome::NoChildNeeded
        }
    }
}

/// One caller waiting for a status condition.
type Listener = (
    Box<dyn Fn(&TxStatus) -> bool + Send>,
    oneshot::Sender<Result<(), DriveErr>>,
);

/// What a bump task does with the result of its bump.
enum BumpFollowUp {
    /// Nothing. The next trigger retries.
    None,
    /// Put the bare parent back when the bump submits no package. The eviction path needs
    /// this: a declined bump leaves the parent in no mempool at all.
    ResubmitBare(BitcoinClient, Transaction),
    /// Carry one job whose bare broadcast failed. The package is its only route into a
    /// mempool, so this job hears the result directly.
    CarryJob {
        /// The error that the bare broadcast reported.
        err: ClientError,
        /// The caller of the failed job. It stays outside the record until the result is
        /// known, so a failure answers this caller alone. Other callers of the same
        /// transaction have their own jobs, and a broadcast failure here says nothing about
        /// those.
        listener: Listener,
        /// Whether the registration of this job created the record. A record that already
        /// existed belongs to an earlier job that still waits on it, and a failure here must
        /// not remove it.
        created: bool,
    },
}

impl BumpFollowUp {
    /// Runs the follow-up for `outcome`.
    ///
    /// [`BumpOutcome::ParentIsLive`] counts as a success for every follow-up. No package went
    /// out, and the parent is in a mempool or in a block, so a bare resubmission is waste and
    /// a failure report to the carried job is wrong.
    async fn apply(
        self,
        parents: &Parents,
        parent_txid: Txid,
        outcome: BumpOutcome,
        mark: Option<&Arc<AtomicBool>>,
    ) {
        let parent_reached_network =
            matches!(outcome, BumpOutcome::Submitted | BumpOutcome::ParentIsLive);
        match self {
            Self::None => {}
            Self::ResubmitBare(rpc_client, rawtx) => {
                if !parent_reached_network {
                    resubmit_bare(&rpc_client, &rawtx, parent_txid).await;
                }
            }
            Self::CarryJob {
                err,
                listener,
                created,
            } => {
                if parent_reached_network {
                    attach_listener(parents, parent_txid, listener).await;
                } else {
                    fail_carried_job(parents, parent_txid, &err, listener, created, mark).await;
                }
            }
        }
    }
}

/// Adds `listener` to the record for `parent_txid`, or answers it when the record is gone.
async fn attach_listener(parents: &Parents, parent_txid: Txid, listener: Listener) {
    if let Some(record) = parents.lock().await.get_mut(&parent_txid) {
        record.listeners.push(listener);
        return;
    }
    // The record went at burial, so the transaction is deep in the chain and no further
    // event can arrive for it.
    let _ = listener.1.send(Err(DriveErr::ConditionUnmet));
}

/// Reports a failed bare broadcast to the one job that made it.
///
/// Removes the record only when this job created it. A record that an earlier job created is
/// still driving that job's transaction, and a later job's broadcast failure says nothing
/// about it.
async fn fail_carried_job(
    parents: &Parents,
    parent_txid: Txid,
    err: &ClientError,
    listener: Listener,
    created: bool,
    mark: Option<&Arc<AtomicBool>>,
) {
    let mut guard = parents.lock().await;
    // The parent reached a block through another route, such as a package that another
    // watchtower submitted. Keep waiting on it instead of reporting a failure.
    if guard
        .get(&parent_txid)
        .is_some_and(|record| record.stage == Stage::Mined)
    {
        if let Some(record) = guard.get_mut(&parent_txid) {
            record.listeners.push(listener);
        }
        return;
    }
    let is_ours = created && mark.is_some_and(|mark| holds_mark(guard.get(&parent_txid), mark));
    if is_ours {
        if let Some(record) = guard.remove(&parent_txid) {
            record.subscription.abort();
        }
    }
    drop(guard);
    let _ = listener.1.send(Err(DriveErr::PublishFailed(err.clone())));
}

/// Takes the bump mark for `parent_txid` when that parent can take a bump now.
///
/// The mark is taken under the records lock, so two triggers cannot both start a bump for one
/// parent.
async fn take_bump_mark(parents: &Parents, parent_txid: Txid) -> Option<BumpGuard> {
    let guard = parents.lock().await;
    match guard.get(&parent_txid) {
        Some(record) if record.stage == Stage::Unconfirmed => {
            record.cpfp.as_ref().and_then(CpfpState::start_bump)
        }
        _ => None,
    }
}

/// Spawns one bump for `parent_txid` after it takes that parent's bump mark.
///
/// Returns the task handle, or `None` when the parent cannot take a bump now. A parent that
/// cannot take one still runs `follow_up`, so an evicted parent goes back into the mempool
/// even when another trigger holds the mark.
///
/// Spawning is not an optimisation. `perform_bump` takes the operator wallet's read lock,
/// and a duty can hold that lock while it awaits `TxDriver::drive`. A bump awaited inside the
/// driver's select loop therefore deadlocks: the driver waits for the wallet, the duty waits
/// for a status event that only the driver can deliver, and neither side can proceed.
///
/// The mark prevents a fault, not duplicate work. Two bumps of one parent take a snapshot of
/// the same handle, and the later write-back drops the lease of the live child.
async fn spawn_bump<W, F, P>(
    ctx: &Arc<CpfpContext<W, F, P>>,
    parents: &Parents,
    parent_txid: Txid,
    bridge_protocol_floor: FeeRate,
    reason: cpfp::BumpReason,
    follow_up: BumpFollowUp,
) -> Option<JoinHandle<()>>
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    let Some(guard) = take_bump_mark(parents, parent_txid).await else {
        // No bump ran, so nothing was learned about the parent.
        follow_up
            .apply(parents, parent_txid, BumpOutcome::NoChildNeeded, None)
            .await;
        return None;
    };
    Some(tokio::spawn({
        let ctx = ctx.clone();
        let parents = parents.clone();
        async move {
            run_bump(
                ctx.as_ref(),
                &parents,
                parent_txid,
                bridge_protocol_floor,
                reason,
                follow_up,
                guard,
            )
            .await;
        }
    }))
}

/// Runs one bump under `guard` and then its follow-up.
async fn run_bump<W, F, P>(
    ctx: &CpfpContext<W, F, P>,
    parents: &Parents,
    parent_txid: Txid,
    bridge_protocol_floor: FeeRate,
    reason: cpfp::BumpReason,
    follow_up: BumpFollowUp,
    guard: BumpGuard,
) where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    let outcome = bump_parent(
        ctx,
        parents,
        parent_txid,
        guard.mark(),
        bridge_protocol_floor,
        reason,
    )
    .await;
    follow_up
        .apply(parents, parent_txid, outcome, Some(guard.mark()))
        .await;
    if outcome == BumpOutcome::Unbumpable {
        // Drop the CPFP state of a record that the follow-up left in place. Its listeners
        // still wait on this transaction, and the eviction path still puts it back bare.
        // The follow-up runs first, because a carried job proves its ownership of the
        // record through the mark that lives in the CPFP state.
        if let Some(record) = parents.lock().await.get_mut(&parent_txid) {
            record.cpfp = None;
        }
    }
}

/// Spawns one task that bumps every parent that can take a bump, one after another.
///
/// The bumps run one at a time. Each one takes the operator wallet's lock, so a
/// parallel fan-out puts every other user of the wallet behind the whole batch. Each parent
/// keeps its own mark, so a parent that another trigger is already bumping is skipped and the
/// rest of the batch continues.
async fn spawn_batch_bump<W, F, P>(
    ctx: &Arc<CpfpContext<W, F, P>>,
    parents: &Parents,
    bridge_protocol_floor: FeeRate,
    reason: cpfp::BumpReason,
) where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    let txids: Vec<Txid> = parents
        .lock()
        .await
        .iter()
        .filter(|(_, record)| record.is_bumpable())
        .map(|(txid, _)| *txid)
        .collect();
    if txids.is_empty() {
        return;
    }
    let ctx = ctx.clone();
    let parents = parents.clone();
    tokio::spawn(async move {
        for parent_txid in txids {
            let Some(guard) = take_bump_mark(&parents, parent_txid).await else {
                continue;
            };
            run_bump(
                ctx.as_ref(),
                &parents,
                parent_txid,
                bridge_protocol_floor,
                reason,
                BumpFollowUp::None,
                guard,
            )
            .await;
        }
    });
}

/// Inserts a record for `job`, or merges the job into the record that already tracks its
/// transaction.
///
/// A duplicate drive job keeps the live CPFP state of the existing record, including the
/// lease of the last child. The duty retry tick re-emits publishes while the state machine
/// waits for burial. A fresh record there drops that lease and strands its inputs.
async fn upsert_parent(
    parents: &Parents,
    tx: Transaction,
    cpfp: Option<CpfpStrategy>,
    subscription: AbortHandle,
    listener: Option<Listener>,
) -> bool {
    let txid = tx.compute_txid();
    let mut guard = parents.lock().await;
    match guard.get_mut(&txid) {
        Some(record) => {
            record.tx = tx;
            record.listeners.extend(listener);
            if let Some(strategy) = cpfp {
                match record.cpfp.as_mut() {
                    Some(cpfp) => cpfp.strategy = strategy,
                    None => record.cpfp = Some(CpfpState::new(strategy)),
                }
            }
            // The record already owns a subscription for this transaction. End the second
            // one, so `SelectAll` drops it on the next poll.
            subscription.abort();
            false
        }
        None => {
            guard.insert(
                txid,
                ParentRecord {
                    tx,
                    listeners: listener.into_iter().collect(),
                    stage: Stage::Unconfirmed,
                    cpfp: cpfp.map(CpfpState::new),
                    subscription,
                },
            );
            true
        }
    }
}

/// System for driving a signed transaction to confirmation.
#[derive(Debug)]
pub struct TxDriver {
    new_jobs_sender: UnboundedSender<TxDriveJob>,
    driver: JoinHandle<()>,
}

/// Lightweight health handle for the transaction driver background worker.
#[derive(Clone, Debug)]
pub struct TxDriverHealthHandle {
    new_jobs_sender: UnboundedSender<TxDriveJob>,
}

impl TxDriverHealthHandle {
    /// Returns true while the transaction driver is still accepting jobs.
    pub fn is_accepting_jobs(&self) -> bool {
        !self.new_jobs_sender.is_closed()
    }
}

impl TxDriver {
    /// Initializes the TxDriver without CPFP fee-bumping. Behaves identically to the original
    /// driver: broadcasts transactions, watches for confirmation, no aggressive bump on
    /// eviction or new blocks. The bump-tick interval is set to a long sentinel duration
    /// (one hour) since no CPFP context is configured — the timer arm fires but the inner
    /// `cpfp_ctx` check short-circuits.
    pub async fn new(zmq_client: BtcNotifyClient<Connected>, rpc_client: BitcoinClient) -> Self {
        Self::with_cpfp::<CpfpDisabled, CpfpDisabled, CpfpDisabled>(
            zmq_client,
            rpc_client,
            None,
            DEFAULT_PROTOCOL_FLOOR,
            NO_CPFP_BUMP_INTERVAL,
        )
        .await
    }

    /// Initializes the TxDriver with CPFP fee-bumping enabled. When `cpfp_ctx` is `Some`, jobs
    /// submitted via [`Self::drive_with_cpfp`] carry a [`CpfpStrategy`], and the driver:
    ///
    /// * On mempool eviction (per-tx ZMQ `Unknown` event): re-queries the fee source, rebuilds the
    ///   child via the wallet, RBF-submits `[parent, child]` as a package.
    /// * On each new block (block-event branch): walks every active CPFP parent that hasn't
    ///   confirmed and runs the same bump path.
    ///
    /// `bridge_protocol_floor` is the bridge presigned-tx fee rate (typically 2 sat/vB). When
    /// the fee source target is at or below this floor, the bump is a no-op — the presigned
    /// parent's own fee already meets the network's needs.
    ///
    /// `bump_check_interval` is the cadence at which the driver polls its cached fee rate
    /// and bumps any active CPFP parent whose package rate is below the new target. The
    /// fee source itself is refreshed in the background by [`crate::cpfp::CachedFeeSource`]
    /// at its own cadence; this knob controls how often the driver consumes that cache.
    /// Defaults to 30 seconds in practice.
    pub async fn with_cpfp<W, F, P>(
        zmq_client: BtcNotifyClient<Connected>,
        rpc_client: BitcoinClient,
        cpfp_ctx: Option<CpfpContext<W, F, P>>,
        bridge_protocol_floor: FeeRate,
        bump_check_interval: std::time::Duration,
    ) -> Self
    where
        W: CpfpWallet + 'static,
        F: CpfpFeeSource + 'static,
        P: CpfpMempool + 'static,
    {
        let new_jobs = unbounded_channel::<TxDriveJob>();
        let new_jobs_sender = new_jobs.0;
        let mut block_subscription = zmq_client.subscribe_blocks().await;

        // The CPFP context is shared via `Arc` so block/tick spawned tasks can capture it
        // by value without forcing `CpfpContext` itself to be Clone-friendly across an
        // ever-cloning hot path.
        let cpfp_ctx = cpfp_ctx.map(Arc::new);

        let driver = tokio::task::spawn(async move {
            let mut new_jobs_receiver_stream = UnboundedReceiverStream::new(new_jobs.1);
            // Each subscription enters through `abortable`, so the record that owns it can
            // end it. `SelectAll` drops a stream that finishes.
            let mut active_tx_subs = SelectAll::<Abortable<Subscription<TxEvent>>>::new();
            let parents: Parents = Arc::new(Mutex::new(HashMap::new()));
            // Timer that fires every `bump_check_interval`. Note the cost model: tick is a
            // reactive `BumpReason`, so it does not take the step-4 same-rate skip. A parent
            // whose probe (step 4.5) reports a live child at a sufficient rate costs one
            // probe and no wallet call. A parent whose probe reports the output unspent is
            // fully rebuilt (wallet build + sign + submitpackage) — deliberate, because a
            // silently-evicted child is invisible and the tick is what revives it. The walk
            // is only cheap in the quiet-mempool steady state, where the floor / parent-fee
            // baseline skips return `NoChildNeeded` before any wallet call.
            let mut bump_tick = tokio::time::interval(bump_check_interval);
            // `Interval::tick` fires immediately on first call. Burn it so the first effective
            // bump tick is one full interval after construction.
            bump_tick.tick().await;
            loop {
                select! {
                    Some(job) = new_jobs_receiver_stream.next().fuse() => {
                        let txid = job.tx.compute_txid();
                        let rawtx = job.tx.clone();
                        let rawtx_filter = job.tx.clone();
                        let (subscription, abort) = abortable(
                            zmq_client
                                .subscribe_transactions(move |tx| tx == &rawtx_filter)
                                .await,
                        );

                        if let Ok(tx_data) = rpc_client.get_raw_transaction_verbosity_one(&txid).await {
                            let num_confirmations = tx_data.confirmations.unwrap_or(0);
                            let block_hash = tx_data.block_hash;
                            let block_height = if let Some(block_hash) = block_hash {
                                // This uses `0` as the default since a block height of `0` does not
                                // satisfy any practical predicate
                                rpc_client.get_block(&block_hash).await.map(|block| block.bip34_block_height().unwrap_or(0)).unwrap_or(0)
                            } else {
                                0
                            };

                            let bury_depth = zmq_client.bury_depth() as u32;
                            let tx_status = match num_confirmations {
                                0 => TxStatus::Mempool,
                                n if n < bury_depth as u64 => TxStatus::Mined {
                                    blockhash: tx_data.block_hash.expect("must be present if confirmed"),
                                    height: block_height,
                                },
                                _ => TxStatus::Buried {
                                    blockhash: tx_data.block_hash.expect("must be present if confirmed"),
                                    height: block_height,
                                },
                            };

                            if job.condition()(&tx_status) {
                                debug!(%txid, %tx_status, "transaction already fulfills the supplied condition, notifying job submitter");
                                if job.respond_on.send(Ok(())).is_err() {
                                    error!("could not send response to job submitter");
                                }
                                abort.abort();
                            } else {
                                // The node already knows this transaction. Track it, so this
                                // caller hears about later status changes, and so CPFP bumps
                                // resume for a parent that an earlier incarnation broadcast
                                // and that is still in the mempool.
                                // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2687>
                                // Handle the race where the relevant event may already have
                                // happened before the subscription is established.
                                active_tx_subs.push(subscription);
                                upsert_parent(&parents, job.tx, job.cpfp, abort, Some((job.condition, job.respond_on))).await;
                                if let Some(ctx) = cpfp_ctx.as_ref() {
                                    spawn_bump(ctx, &parents, txid, bridge_protocol_floor, BumpReason::NewJob, BumpFollowUp::None).await;
                                }
                            }

                            continue;
                        }

                        let options = broadcast_options(&rawtx);
                        match rpc_client.send_raw_transaction(&rawtx, options).await {
                            Ok(txid) => {
                                info!(%txid, "broadcasted transaction successfully");
                                active_tx_subs.push(subscription);
                                upsert_parent(&parents, job.tx, job.cpfp, abort, Some((job.condition, job.respond_on))).await;
                                if let Some(ctx) = cpfp_ctx.as_ref() {
                                    spawn_bump(ctx, &parents, txid, bridge_protocol_floor, BumpReason::NewJob, BumpFollowUp::None).await;
                                }
                            },
                            Err(err) => {
                                // Bare broadcast failed. Most commonly the parent's own fee
                                // rate is below the mempool's minimum and a CPFP child can
                                // carry it in via `submitpackage` (package validation is
                                // more lenient than single-tx acceptance). If CPFP is
                                // configured, try that fallback before failing the job.
                                // `BumpFallback::FailJob` reports the broadcast error and
                                // removes the record when the package does not land either.
                                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2689>
                                // Distinguish invalid transactions and notify the job
                                // submitter directly instead of attempting fee bumping.
                                match (cpfp_ctx.as_ref(), job.cpfp.is_some()) {
                                    (Some(ctx), true) => {
                                        warn!(%txid, %err, "bare broadcast failed; attempting CPFP package fallback");
                                        active_tx_subs.push(subscription);
                                        // `Defer` keeps this caller out of the record. The
                                        // package attempt answers it directly, so a failure
                                        // reaches this caller alone and leaves any earlier
                                        // job on the same transaction untouched.
                                        let listener = (job.condition, job.respond_on);
                                        let created =
                                            upsert_parent(&parents, job.tx, job.cpfp, abort, None).await;
                                        spawn_bump(
                                            ctx,
                                            &parents,
                                            txid,
                                            bridge_protocol_floor,
                                            BumpReason::NewJob,
                                            BumpFollowUp::CarryJob { err, listener, created },
                                        )
                                        .await;
                                    }
                                    _ => {
                                        error!(%txid, tx=?rawtx, %err, "could not submit transaction");
                                        abort.abort();
                                        if job.respond_on.send(Err(DriveErr::PublishFailed(err))).is_err() {
                                            error!("could not send error response to job submitter");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Some(event) = active_tx_subs.next().fuse() => {
                        let txid = event.rawtx.compute_txid();
                        match event.status {
                            TxStatus::Unknown => {
                                // Evicted from the mempool. A parent with CPFP rebuilds its
                                // child at the current target and re-submits the package.
                                // Everything else goes back bare.
                                let has_cpfp = {
                                    let mut guard = parents.lock().await;
                                    match guard.get_mut(&txid) {
                                        Some(record) => {
                                            // An eviction of a mined parent means a reorg
                                            // dropped it from its block and from the
                                            // mempool. That is what the bumps exist for.
                                            if record.stage == Stage::Mined {
                                                info!(%txid, "mined parent evicted after a reorg; resuming CPFP bumps");
                                                record.stage = Stage::Unconfirmed;
                                            }
                                            record.cpfp.is_some()
                                        }
                                        None => false,
                                    }
                                };
                                match (cpfp_ctx.as_ref(), has_cpfp) {
                                    (Some(ctx), true) => {
                                        spawn_bump(
                                            ctx,
                                            &parents,
                                            txid,
                                            bridge_protocol_floor,
                                            BumpReason::ParentEvicted,
                                            BumpFollowUp::ResubmitBare(rpc_client.clone(), event.rawtx.clone()),
                                        )
                                        .await;
                                    }
                                    _ => resubmit_bare(&rpc_client, &event.rawtx, txid).await,
                                }
                            }
                            status => {
                                // CPFP lifecycle against confirmation depth:
                                //
                                // - Mined: stop the bumps (a confirmed parent needs no
                                //   child) and drop the lease of the last child. Almost
                                //   every caller waits for burial, so the record stays. A
                                //   reorg between mined and buried returns the
                                //   parent to the mempool (`Mempool`) or evicts it
                                //   (`Unknown`), and the bumps resume then.
                                // - Mempool: wake a record that the Mined arm stopped. A
                                //   reorg is the only cause of that.
                                // - Buried: final. Remove the record, which ends the
                                //   subscription and drops any lease the Mined arm did not
                                //   already drop.
                                //
                                // If the parent confirmed through a competitor's child, the
                                // drop frees our dead child's funding. If our own child
                                // confirmed, its funding is spent on chain — see the release
                                // note in `perform_bump` step 4.5 for the bounded side
                                // effect. A woken record starts from an empty handle and
                                // takes a fresh lease on its next bump.
                                let mut guard = parents.lock().await;
                                let Some(record) = guard.get_mut(&txid) else {
                                    continue;
                                };
                                record.notify(&status);
                                match status {
                                    TxStatus::Mined { .. } => {
                                        record.stage = Stage::Mined;
                                        if let Some(cpfp) = record.cpfp.as_mut() {
                                            cpfp.handle = CpfpHandle::default();
                                        }
                                    }
                                    TxStatus::Mempool => {
                                        if record.stage == Stage::Mined {
                                            info!(%txid, "parent reorged back into the mempool; resuming CPFP bumps");
                                            record.stage = Stage::Unconfirmed;
                                        }
                                    }
                                    TxStatus::Buried { .. } => {
                                        if let Some(record) = guard.remove(&txid) {
                                            record.subscription.abort();
                                            // The driver stops tracking a buried
                                            // transaction, so a condition that is still
                                            // false can never become true. Say so, rather
                                            // than drop the channel and leave the caller to
                                            // read a dropped sender as an aborted driver.
                                            for (_, respond_on) in record.listeners {
                                                let _ = respond_on
                                                    .send(Err(DriveErr::ConditionUnmet));
                                            }
                                        }
                                    }
                                    TxStatus::Unknown => {}
                                }
                            }
                        }
                    }
                    _block = block_subscription.next().fuse() => {
                        // On each new block, walk every tracked parent and spawn a bump for
                        // each one that can take it. Spawned (not inline) so the driver
                        // returns to its select! immediately, and because a bump takes the
                        // operator wallet's lock — see `spawn_bump` for why an inline bump
                        // deadlocks.
                        if let Some(ctx) = cpfp_ctx.as_ref() {
                            spawn_batch_bump(ctx, &parents, bridge_protocol_floor, BumpReason::NewBlock).await;
                        }
                    }
                    _ = bump_tick.tick().fuse() => {
                        // Periodic timer-driven bump — same shape as the new-block arm.
                        if let Some(ctx) = cpfp_ctx.as_ref() {
                            spawn_batch_bump(ctx, &parents, bridge_protocol_floor, BumpReason::Tick).await;
                        }
                    }
                }
            }
        });

        TxDriver {
            new_jobs_sender,
            driver,
        }
    }

    /// Instructs the TxDriver to drive a new transaction to confirmation without CPFP.
    pub async fn drive(
        &self,
        tx: Transaction,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
    ) -> Result<(), DriveErr> {
        self.drive_inner(tx, condition, None).await
    }

    /// Instructs the TxDriver to drive a new transaction to confirmation with CPFP
    /// fee-bumping. The driver builds the initial child immediately (unless the fee source
    /// reports at or below the bridge protocol floor), then RBFs the child on each new block
    /// or mempool eviction until the parent confirms or the operator's `max_fee_rate` cap is
    /// reached.
    ///
    /// Requires the driver to have been initialized via [`Self::with_cpfp`] with a non-`None`
    /// [`CpfpContext`]. If CPFP wasn't configured at construction time, this method behaves
    /// the same as [`Self::drive`].
    pub async fn drive_with_cpfp(
        &self,
        tx: Transaction,
        cpfp: CpfpStrategy,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
    ) -> Result<(), DriveErr> {
        self.drive_inner(tx, condition, Some(cpfp)).await
    }

    async fn drive_inner(
        &self,
        tx: Transaction,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
        cpfp: Option<CpfpStrategy>,
    ) -> Result<(), DriveErr> {
        let (sender, receiver) = oneshot::channel();
        self.new_jobs_sender
            .send(TxDriveJob {
                tx,
                condition: Box::new(condition),
                respond_on: sender,
                cpfp,
            })
            .map_err(|_| DriveErr::DriverAborted)?;
        receiver
            .await
            .map_err(|_| DriveErr::DriverAborted)
            .flatten()
    }

    /// Returns a cloneable health handle for observing the background worker.
    pub fn health_handle(&self) -> TxDriverHealthHandle {
        TxDriverHealthHandle {
            new_jobs_sender: self.new_jobs_sender.clone(),
        }
    }
}

impl Drop for TxDriver {
    /// Aborts the main driver task. Each in-flight bump task is detached, and a detached
    /// bump runs to the end of its current attempt. The records map is behind an [`Arc`]: the
    /// driver task drops its clone, and the map goes when the last bump task ends.
    ///
    /// At process shutdown the runtime tears those tasks down. A restart of `TxDriver` inside
    /// one process can race the bump tasks of the previous instance for a short time. That
    /// race is safe: each bump takes the wallet lock per attempt and releases it between
    /// attempts, and the records map belongs to one `TxDriver`, so an old task reads only its
    /// own map. If a mid-process `TxDriver` lifecycle becomes load-bearing, add a
    /// `shutdown(self)` that awaits the in-flight bumps before it aborts the driver task.
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{absolute, transaction, Amount, ScriptBuf, Transaction, TxOut};

    use super::broadcast_options;

    fn tx_with_outputs(output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output,
        }
    }

    #[test]
    fn broadcast_options_use_largest_op_return_burn() {
        let tx = tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([1u8; 32]),
            },
            TxOut {
                value: Amount::from_sat(2_000),
                script_pubkey: ScriptBuf::new_op_return([2u8; 32]),
            },
            TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: ScriptBuf::new(),
            },
        ]);

        let options = broadcast_options(&tx).expect("OP_RETURN burn must require options");

        assert_eq!(options.max_burn_amount, Some(Amount::from_sat(2_000)));
    }
}

#[cfg(test)]
mod e2e_tests {
    use std::{collections::VecDeque, path::PathBuf, sync::Arc};

    use algebra::predicate;
    use bitcoin::{
        absolute, transaction, Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness,
    };
    use bitcoind_async_client::Client as BitcoinClient;
    use corepc_node::{client::client_sync::Auth, vtype::FundRawTransaction, CookieValues, Output};
    use futures::join;
    use serial_test::serial;
    use strata_bridge_common::logging;
    use strata_bridge_test_utils::prelude::wait_for_height;
    use tracing::{debug, info};

    use super::*;
    use crate::{client::BlockFetcher, config::BtcNotifyConfig};

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2692>
    // Remove this once rust-bitcoin@0.33.x lands; it works around a rust-bitcoin bug.
    pub(crate) const BIP34_MIN_BLOCKS: usize = 17;

    fn setup_fetcher(rpc_url: &str, cookie_file: PathBuf) -> impl BlockFetcher<Error = String> {
        struct Fetcher(corepc_node::Client);

        #[async_trait::async_trait]
        impl BlockFetcher for Fetcher {
            type Error = String;

            async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
                let hash = self
                    .0
                    .get_block_hash(height)
                    .map_err(|e| e.to_string())?
                    .block_hash()
                    .expect("must be valid hash");
                let block = self.0.get_block(hash).map_err(|e| e.to_string())?;

                Ok(block)
            }
        }

        let auth = Auth::CookieFile(cookie_file);
        let client = corepc_node::Client::new_with_auth(rpc_url, auth)
            .expect("must be able to create client");

        Fetcher(client)
    }

    async fn setup() -> Result<(TxDriver, corepc_node::Node), Box<dyn std::error::Error>> {
        let mut bitcoin_conf = corepc_node::Conf::default();
        bitcoin_conf.enable_zmq = true;

        // TODO: <https://alpenlabs.atlassian.net/browse/STR-2681>
        // Use dynamic port allocation so these tests can run in parallel.
        let hash_block_socket = "tcp://127.0.0.1:23882";
        let hash_tx_socket = "tcp://127.0.0.1:23883";
        let raw_block_socket = "tcp://127.0.0.1:23884";
        let raw_tx_socket = "tcp://127.0.0.1:23885";
        let sequence_socket = "tcp://127.0.0.1:23886";
        let args = [
            format!("-zmqpubhashblock={hash_block_socket}"),
            format!("-zmqpubhashtx={hash_tx_socket}"),
            format!("-zmqpubrawblock={raw_block_socket}"),
            format!("-zmqpubrawtx={raw_tx_socket}"),
            format!("-zmqpubsequence={sequence_socket}"),
            // NOTE: (@Rajil1213) without this, the node will respond with status code 500
            // when rebroadcasting or querying for mined transactions, causing idempotence tests to
            // fail or become flaky.
            "-txindex=1".to_string(),
        ];
        bitcoin_conf.args.extend(args.iter().map(String::as_str));
        let bitcoind = corepc_node::Node::with_conf("bitcoind", &bitcoin_conf)?;

        bitcoind
            .client
            .generate_to_address(BIP34_MIN_BLOCKS, &bitcoind.client.new_address()?)?;

        debug!("corepc_node::Node initialized");

        let cfg = BtcNotifyConfig::default()
            .with_hashblock_connection_string(hash_block_socket)
            .with_hashtx_connection_string(hash_tx_socket)
            .with_rawblock_connection_string(raw_block_socket)
            .with_rawtx_connection_string(raw_tx_socket)
            .with_sequence_connection_string(sequence_socket);

        let zmq_client = BtcNotifyClient::new(&cfg, VecDeque::new());
        let start_height = bitcoind.client.get_block_count()?.0;
        let cookie_file = bitcoind.params.cookie_file.clone();
        let fetcher = setup_fetcher(&bitcoind.rpc_url(), cookie_file);
        let zmq_client = zmq_client.connect(start_height, fetcher).await?;
        debug!("BtcNotifyClient initialized");

        let CookieValues { user, password } = bitcoind
            .params
            .get_cookie_values()
            .expect("can read cookie")
            .expect("can parse cookie");
        let auth = bitcoind_async_client::Auth::UserPass(user, password);
        let rpc_client = BitcoinClient::new(bitcoind.rpc_url(), auth, None, None, None)
            .expect("can set up rpc client");
        debug!("bitcoin_async_client::Client initialized");

        let tx_driver = TxDriver::new(zmq_client, rpc_client).await;
        debug!("TxDriver initialized");

        Ok((tx_driver, bitcoind))
    }

    #[tokio::test]
    #[serial]
    async fn tx_drive_idempotence() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("tx_drive_idempotence");

        let (driver, bitcoind) = setup().await?;

        let new_address = bitcoind.client.new_address()?;
        // Mine 101 new blocks to that same address. We use 101 so that the coins minted in the
        // first block can be spent which we will need to do for the remainder of the test.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        debug!("waiting for test funds to mature");
        wait_for_height(&bitcoind, 101).await?;
        debug!("test funds matured");

        debug!("creating raw transaction");
        let out = Output::new(new_address.clone(), Amount::from_btc(1.0)?);
        // Get hex string directly - don't use into_model() as 0-input transactions
        // can't be deserialized due to segwit marker ambiguity
        let raw_hex = bitcoind.client.create_raw_transaction(&[], &[out])?.0;
        debug!(%raw_hex, "created raw transaction");

        debug!("funding raw transaction");
        // Use call() directly to pass hex string since fund_raw_transaction expects &Transaction
        let funded_result: FundRawTransaction = bitcoind
            .client
            .call("fundrawtransaction", &[raw_hex.into()])?;
        let funded = funded_result.into_model()?.tx;
        debug!(funded=%funded.compute_txid(), "funded raw transaction");

        debug!("signing raw transaction");
        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&funded)?
            .into_model()?
            .tx;
        debug!(signed=%signed.compute_txid(), "signed raw transaction");

        info!("sending first copy to TxDriver");
        let fst = driver.drive(signed.clone(), TxStatus::is_buried);
        info!("sending second copy to TxDriver");
        let snd = driver.drive(signed, TxStatus::is_buried);

        info!("starting mining task");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_thread = stop.clone();
        let mine_task = tokio::task::spawn_blocking(move || {
            while !stop_thread.load(std::sync::atomic::Ordering::SeqCst) {
                bitcoind
                    .client
                    .generate_to_address(1, &new_address)
                    .unwrap();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });

        debug!("waiting for TxDriver::drive calls to complete");
        let (fst_res, snd_res) = join!(fst, snd);
        info!("TxDriver::drive calls completed");

        debug!("terminating mining task");
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(1), mine_task).await??;
        info!("mining task terminated");

        fst_res.expect("first drive succeeds");
        snd_res.expect("second drive succeeds");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn tx_drive_mempool() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("tx_drive_idempotence");

        let (driver, bitcoind) = setup().await?;

        let new_address = bitcoind.client.new_address()?;
        // Mine 101 new blocks to that same address. We use 101 so that the coins minted in the
        // first block can be spent which we will need to do for the remainder of the test.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        debug!("waiting for test funds to mature");
        wait_for_height(&bitcoind, 101).await?;
        debug!("test funds matured");

        debug!("creating raw transaction");
        let outs = vec![Output::new(new_address, Amount::from_btc(1.0)?)];
        // Get hex string directly - don't use into_model() as 0-input transactions
        // can't be deserialized due to segwit marker ambiguity
        let raw_hex = bitcoind.client.create_raw_transaction(&[], &outs)?.0;
        debug!(%raw_hex, "created raw transaction");

        debug!("funding raw transaction");
        // Use call() directly to pass hex string since fund_raw_transaction expects &Transaction
        let funded_result: FundRawTransaction = bitcoind
            .client
            .call("fundrawtransaction", &[raw_hex.into()])?;
        let funded = funded_result.into_model()?.tx;
        debug!(funded=%funded.compute_txid(), "funded raw transaction");

        debug!("signing raw transaction");
        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&funded)?
            .into_model()?
            .tx;
        debug!(signed=%signed.compute_txid(), "signed raw transaction");

        info!("driving to mempool");
        driver
            .drive(signed, predicate::eq(TxStatus::Mempool))
            .await?;
        info!("transaction appeared in mempool");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn tx_drive_op_return_burn() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("tx_drive_op_return_burn");

        let (driver, bitcoind) = setup().await?;

        let new_address = bitcoind.client.new_address()?;
        let blocks = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        debug!("waiting for test funds to mature");
        wait_for_height(&bitcoind, 101).await?;
        debug!("test funds matured");

        let spendable_block = bitcoind.client.get_block(
            *blocks
                .0
                .first()
                .expect("generate_to_address must return mined block hashes"),
        )?;
        let coinbase_tx = spendable_block
            .coinbase()
            .expect("mined block must contain a coinbase transaction");

        let burn_amount = Amount::from_sat(1_000);
        let fee = Amount::from_sat(10_000);
        let change_amount = coinbase_tx.output[0].value - burn_amount - fee;
        let change_address = bitcoind.client.new_address()?;
        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(coinbase_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: burn_amount,
                    script_pubkey: ScriptBuf::new_op_return([1u8; 32]),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
        };

        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&unsigned)?
            .into_model()?
            .tx;

        let err = bitcoind
            .client
            .send_raw_transaction(&signed)
            .expect_err("default maxburnamount must reject OP_RETURN burns");
        let err = err.to_string();
        assert!(
            err.contains("maxburnamount") || err.contains("max-burn-amount"),
            "unexpected sendrawtransaction error: {err}"
        );

        info!("driving OP_RETURN burn to mempool");
        driver
            .drive(signed.clone(), predicate::eq(TxStatus::Mempool))
            .await?;
        info!("OP_RETURN burn transaction appeared in mempool");

        Ok(())
    }
}

/// Unit tests for the driver's CPFP entry-lifecycle plumbing, using the shared fakes from
/// [`crate::cpfp::tests`]. The full driver loop needs a live bitcoind (see `e2e_tests`); these
/// pin the helpers the loop is built from, which is where the audit found the lifecycle gaps.
#[cfg(test)]
mod cpfp_lifecycle_tests {
    use std::collections::HashMap;

    use bitcoin::{Amount, OutPoint, XOnlyPublicKey};

    use super::*;
    use crate::cpfp::{
        tests::{
            anchor_strategy, fake_input_signer_ok, synthetic_child_psbt, synthetic_parent,
            test_keypair_and_xonly, FakeFeeSource, FakeSubmitter, FakeWallet, PROTOCOL_FLOOR,
        },
        CpfpContext,
    };

    fn test_ctx(
        wallet: FakeWallet,
        submitter: FakeSubmitter,
    ) -> CpfpContext<FakeWallet, FakeFeeSource, FakeSubmitter> {
        CpfpContext {
            wallet: Arc::new(wallet),
            fee_source: Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            anchor_input_signer: fake_input_signer_ok(),
            multi_anchor_signer: fake_input_signer_ok(),
            wallet_input_signer: fake_input_signer_ok(),
            max_fee_rate: FeeRate::from_sat_per_vb(20).unwrap(),
            // Neutral fee knobs: the tx_driver tests pin the raw-estimate-to-cap behavior.
            fee_premium_percent: 0,
            min_package_fee_rate: FeeRate::from_sat_per_vb_unchecked(0),
            mempool: Arc::new(submitter),
        }
    }

    /// Builds a record whose CPFP state is fresh and whose subscription handle is inert.
    fn test_record(parent: Transaction, key: XOnlyPublicKey, stage: Stage) -> ParentRecord {
        ParentRecord {
            tx: parent,
            listeners: Vec::new(),
            stage,
            cpfp: Some(CpfpState::new(anchor_strategy(key))),
            subscription: AbortHandle::new_pair().0,
        }
    }

    /// Returns the records map and the bump mark of the single record it holds.
    fn parents_with(txid: Txid, record: ParentRecord) -> (Parents, Arc<AtomicBool>) {
        let mark = Arc::clone(&record.cpfp.as_ref().expect("cpfp state").bumping);
        (Arc::new(Mutex::new(HashMap::from([(txid, record)]))), mark)
    }

    /// A listener that no status satisfies, paired with the receiver that hears its outcome.
    fn never_listener() -> (Listener, oneshot::Receiver<Result<(), DriveErr>>) {
        let (respond_on, receiver) = oneshot::channel();
        ((Box::new(|_| false), respond_on), receiver)
    }

    /// A mined parent is not bumped: a confirmed parent needs no child. The same record at
    /// `Unconfirmed` submits, so the stage is the only difference under test.
    #[tokio::test]
    async fn bump_parent_skips_mined_parents() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let funding = vec![OutPoint {
            txid: parent_txid,
            vout: 7,
        }];

        for (stage, expect_submit) in [(Stage::Mined, false), (Stage::Unconfirmed, true)] {
            let submitter = Arc::new(FakeSubmitter::ok());
            let ctx = CpfpContext {
                wallet: Arc::new(FakeWallet::returning(
                    synthetic_child_psbt(&parent, 0, key),
                    funding.clone(),
                )),
                fee_source: Arc::new(FakeFeeSource::returning(
                    FeeRate::from_sat_per_vb(10).unwrap(),
                )),
                anchor_input_signer: fake_input_signer_ok(),
                multi_anchor_signer: fake_input_signer_ok(),
                wallet_input_signer: fake_input_signer_ok(),
                max_fee_rate: FeeRate::from_sat_per_vb(20).unwrap(),
                // Neutral fee knobs: the tx_driver tests pin the raw-estimate-to-cap behavior.
                fee_premium_percent: 0,
                min_package_fee_rate: FeeRate::from_sat_per_vb_unchecked(0),
                mempool: submitter.clone(),
            };
            let (parents, mark) =
                parents_with(parent_txid, test_record(parent.clone(), key, stage));

            let submitted = bump_parent(
                &ctx,
                &parents,
                parent_txid,
                &mark,
                PROTOCOL_FLOOR,
                BumpReason::Tick,
            )
            .await;

            assert_eq!(
                submitted == BumpOutcome::Submitted,
                expect_submit,
                "stage = {stage:?}"
            );
            assert_eq!(
                submitter.captured.lock().unwrap().len(),
                usize::from(expect_submit),
                "stage = {stage:?}"
            );
        }
    }

    /// Even a failed bump must land its handle back in the record. `perform_bump` takes the
    /// lease on the new child's funding inputs before the steps that can fail, and the next
    /// bump can only reuse those inputs if that update survives into the record.
    #[tokio::test]
    async fn bump_parent_writes_handle_back_on_submit_failure() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let funding = vec![OutPoint {
            txid: parent_txid,
            vout: 7,
        }];
        let psbt = synthetic_child_psbt(&parent, 0, key);
        let ctx = test_ctx(
            FakeWallet::returning(psbt, funding.clone()),
            FakeSubmitter::failing("package-not-valid"),
        );
        let (parents, mark) = parents_with(
            parent_txid,
            test_record(parent.clone(), key, Stage::Unconfirmed),
        );

        let submitted = bump_parent(
            &ctx,
            &parents,
            parent_txid,
            &mark,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
        )
        .await;

        assert_ne!(
            submitted,
            BumpOutcome::Submitted,
            "rejected package must not report submission"
        );
        let map = parents.lock().await;
        let cpfp = map[&parent_txid].cpfp.as_ref().expect("cpfp state");
        assert_eq!(
            cpfp.handle
                .last_child_lease
                .as_deref()
                .expect("the record must hold a lease")
                .outpoints(),
            funding,
            "the lease must be written back even though submission failed"
        );
        assert!(
            cpfp.handle.last_child_txid.is_none(),
            "nothing reached the mempool, so the child txid must not advance"
        );
    }

    /// A vanished record (parent buried between look-up and bump) is a quiet no-op — in
    /// particular the wallet must never be asked to fund a child for it.
    #[tokio::test]
    async fn bump_parent_is_noop_when_the_record_vanished() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let ctx = test_ctx(
            FakeWallet::failing("wallet must not be called for a vanished record"),
            FakeSubmitter::failing("submitter must not be called either"),
        );
        let parents: Parents = Arc::new(Mutex::new(HashMap::new()));

        let submitted = bump_parent(
            &ctx,
            &parents,
            parent.compute_txid(),
            &Arc::new(AtomicBool::new(true)),
            PROTOCOL_FLOOR,
            BumpReason::NewBlock,
        )
        .await;

        assert_ne!(submitted, BumpOutcome::Submitted);
        assert!(parents.lock().await.is_empty());
    }

    /// The package fallback is the last chance for a parent that bare broadcast rejected.
    /// When it fails too, the record must go. Nothing else removes it, and every block and
    /// tick bumps it. Its caller must hear the broadcast error rather than wait forever.
    #[tokio::test]
    async fn a_failed_package_fallback_removes_the_record_and_reports_the_error() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let ctx = Arc::new(test_ctx(
            FakeWallet::returning(
                synthetic_child_psbt(&parent, 0, key),
                vec![OutPoint {
                    txid: parent_txid,
                    vout: 7,
                }],
            ),
            FakeSubmitter::failing("package-not-valid"),
        ));
        let (parents, _mark) =
            parents_with(parent_txid, test_record(parent, key, Stage::Unconfirmed));
        let (listener, receiver) = never_listener();

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
            BumpFollowUp::CarryJob {
                err: ClientError::Other("bare broadcast rejected".into()),
                listener,
                created: true,
            },
        )
        .await
        .expect("a bumpable record must spawn a bump");
        task.await.expect("the bump task must not panic");

        assert!(
            parents.lock().await.is_empty(),
            "a failed fallback must remove the record that it created"
        );
        assert!(
            matches!(receiver.await, Ok(Err(DriveErr::PublishFailed(_)))),
            "the caller must hear the broadcast error"
        );
    }

    /// A record that an earlier job created is still driving that job's transaction. A later
    /// job whose bare broadcast failed must not remove that record, and must not answer the
    /// earlier caller with its own broadcast error.
    #[tokio::test]
    async fn a_failed_package_fallback_leaves_an_earlier_jobs_record_alone() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let ctx = Arc::new(test_ctx(
            FakeWallet::returning(
                synthetic_child_psbt(&parent, 0, key),
                vec![OutPoint {
                    txid: parent_txid,
                    vout: 7,
                }],
            ),
            FakeSubmitter::failing("package-not-valid"),
        ));
        let mut record = test_record(parent, key, Stage::Unconfirmed);
        let (earlier, mut earlier_receiver) = never_listener();
        record.listeners.push(earlier);
        let (parents, _mark) = parents_with(parent_txid, record);
        let (listener, receiver) = never_listener();

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
            BumpFollowUp::CarryJob {
                err: ClientError::Other("bare broadcast rejected".into()),
                listener,
                // The registration of the later job found the record already there.
                created: false,
            },
        )
        .await
        .expect("a bumpable record must spawn a bump");
        task.await.expect("the bump task must not panic");

        assert!(
            parents.lock().await.contains_key(&parent_txid),
            "the earlier job's record must survive a later job's broadcast failure"
        );
        assert!(
            matches!(receiver.await, Ok(Err(DriveErr::PublishFailed(_)))),
            "the later caller must hear its own broadcast error"
        );
        // `try_recv` and not `await`: the earlier caller is still waiting, so an await here
        // never returns.
        assert!(
            matches!(earlier_receiver.try_recv(), Ok(None)),
            "the earlier caller must still be waiting for its own outcome"
        );
    }

    /// A bump that cannot start must still run its follow-up. The eviction path is the only
    /// place that puts an evicted parent back in the mempool, so a declined bump that drops
    /// its follow-up leaves that parent in no mempool at all.
    #[tokio::test]
    async fn a_declined_bump_still_reports_its_carried_job() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let ctx = Arc::new(test_ctx(
            FakeWallet::failing("wallet must not be called while a bump runs"),
            FakeSubmitter::failing("submitter must not be called either"),
        ));
        let (parents, mark) =
            parents_with(parent_txid, test_record(parent, key, Stage::Unconfirmed));
        // Stand in for a bump that another trigger already started.
        mark.store(true, Ordering::Release);
        let (listener, receiver) = never_listener();

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
            BumpFollowUp::CarryJob {
                err: ClientError::Other("bare broadcast rejected".into()),
                listener,
                created: true,
            },
        )
        .await;

        assert!(
            task.is_none(),
            "a marked parent must not spawn a second bump"
        );
        assert!(
            matches!(receiver.await, Ok(Err(DriveErr::PublishFailed(_)))),
            "a declined bump must still answer the job that it carries"
        );
    }

    /// The successful fallback keeps its record, so the confirmation path owns it from here,
    /// the record carries the lease that the bump took, and the carried caller joins it.
    #[tokio::test]
    async fn a_successful_package_fallback_keeps_the_record_and_its_lease() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let funding = vec![OutPoint {
            txid: parent_txid,
            vout: 7,
        }];
        let ctx = Arc::new(test_ctx(
            FakeWallet::returning(synthetic_child_psbt(&parent, 0, key), funding.clone()),
            FakeSubmitter::ok(),
        ));
        let (parents, _mark) =
            parents_with(parent_txid, test_record(parent, key, Stage::Unconfirmed));
        let (listener, _receiver) = never_listener();

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
            BumpFollowUp::CarryJob {
                err: ClientError::Other("must not be reported".into()),
                listener,
                created: true,
            },
        )
        .await
        .expect("a bumpable record must spawn a bump");
        task.await.expect("the bump task must not panic");

        let map = parents.lock().await;
        let record = &map[&parent_txid];
        let cpfp = record.cpfp.as_ref().expect("cpfp state");
        assert_eq!(
            cpfp.handle
                .last_child_lease
                .as_deref()
                .expect("the record must hold a lease")
                .outpoints(),
            funding,
            "the surviving record must carry the lease that the bump took"
        );
        assert_eq!(
            record.listeners.len(),
            1,
            "the carried caller joins the record once the package lands"
        );
    }

    /// An unbumpable parent that entered through a failed bare broadcast must go completely.
    /// The package was its only route into a mempool, so the record that its job created is
    /// removed, and its caller hears the broadcast error.
    #[tokio::test]
    async fn an_unbumpable_carried_job_still_removes_its_record() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let ctx = Arc::new(test_ctx(
            FakeWallet::unbumpable("anchor vout 9 out of range"),
            FakeSubmitter::failing("submitter must not be called"),
        ));
        let (parents, _mark) =
            parents_with(parent_txid, test_record(parent, key, Stage::Unconfirmed));
        let (listener, receiver) = never_listener();

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
            BumpFollowUp::CarryJob {
                err: ClientError::Other("bare broadcast rejected".into()),
                listener,
                created: true,
            },
        )
        .await
        .expect("a bumpable record must spawn a bump");
        task.await.expect("the bump task must not panic");

        assert!(
            parents.lock().await.is_empty(),
            "the record must go with the job that created it"
        );
        assert!(
            matches!(receiver.await, Ok(Err(DriveErr::PublishFailed(_)))),
            "the caller must hear the broadcast error"
        );
    }

    /// The contention outcome depends on which package member lost the race. A rejection on
    /// the parent means a conflicting transaction is in the mempool and the parent is not.
    /// A rejection on the child means the incumbent spends an output of the parent, so the
    /// parent is in a mempool.
    #[tokio::test]
    async fn contention_on_the_parent_itself_is_not_proof_of_life() {
        use bitcoin::hashes::Hash;
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let funding = vec![OutPoint {
            txid: parent_txid,
            vout: 7,
        }];
        let marker = "insufficient fee, rejecting replacement";

        for (rejected, expected) in [
            (parent_txid, BumpOutcome::NoChildNeeded),
            (Txid::from_byte_array([0xEE; 32]), BumpOutcome::ParentIsLive),
        ] {
            let ctx = test_ctx(
                FakeWallet::returning(synthetic_child_psbt(&parent, 0, key), funding.clone()),
                FakeSubmitter::failing("package rbf failure").with_tx_error(rejected, marker),
            );
            let (parents, mark) = parents_with(
                parent_txid,
                test_record(parent.clone(), key, Stage::Unconfirmed),
            );
            let outcome = bump_parent(
                &ctx,
                &parents,
                parent_txid,
                &mark,
                PROTOCOL_FLOOR,
                BumpReason::Tick,
            )
            .await;
            assert_eq!(outcome, expected, "rejected member = {rejected}");
        }
    }

    /// A parent whose anchor the wallet cannot spend never becomes bumpable. The driver drops
    /// its CPFP state, so no later block or tick rebuilds, re-signs, and resubmits for it.
    /// The record stays, because its callers still wait on the transaction.
    #[tokio::test]
    async fn an_unbumpable_parent_loses_its_cpfp_state() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let ctx = Arc::new(test_ctx(
            FakeWallet::unbumpable("anchor vout 9 out of range"),
            FakeSubmitter::failing("submitter must not be called"),
        ));
        let (parents, _mark) =
            parents_with(parent_txid, test_record(parent, key, Stage::Unconfirmed));

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
            BumpFollowUp::None,
        )
        .await
        .expect("a bumpable record must spawn a bump");
        task.await.expect("the bump task must not panic");

        let map = parents.lock().await;
        let record = map.get(&parent_txid).expect("the record must survive");
        assert!(
            record.cpfp.is_none(),
            "an unbumpable parent must lose its CPFP state"
        );
        assert!(!record.is_bumpable(), "and it must not take another bump");
    }

    /// The per-parent mark stops a second trigger from bumping a parent whose bump is still
    /// running. Two concurrent bumps snapshot one handle, and the later write-back drops the
    /// lease that the earlier one took.
    #[tokio::test]
    async fn a_second_trigger_does_not_bump_a_parent_that_is_already_bumping() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let (parents, bumping) =
            parents_with(parent_txid, test_record(parent, key, Stage::Unconfirmed));

        // Stand in for a bump that is still running.
        bumping.store(true, Ordering::Release);
        let ctx = Arc::new(test_ctx(
            FakeWallet::failing("wallet must not be called while a bump runs"),
            FakeSubmitter::failing("submitter must not be called either"),
        ));

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
            BumpFollowUp::None,
        )
        .await;

        assert!(task.is_none(), "the second trigger must not spawn a bump");
    }

    /// The mark clears when the bump task ends, so the next trigger can bump again.
    #[tokio::test]
    async fn the_bump_mark_clears_when_the_bump_ends() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let (parents, bumping) = parents_with(
            parent_txid,
            test_record(parent.clone(), key, Stage::Unconfirmed),
        );
        let ctx = Arc::new(test_ctx(
            FakeWallet::returning(
                synthetic_child_psbt(&parent, 0, key),
                vec![OutPoint {
                    txid: parent_txid,
                    vout: 7,
                }],
            ),
            FakeSubmitter::ok(),
        ));

        let task = spawn_bump(
            &ctx,
            &parents,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
            BumpFollowUp::None,
        )
        .await
        .expect("a bumpable record must spawn a bump");
        assert!(bumping.load(Ordering::Acquire), "the mark is taken");
        task.await.expect("the bump task must not panic");
        assert!(
            !bumping.load(Ordering::Acquire),
            "the mark must clear when the bump ends"
        );
    }
}
