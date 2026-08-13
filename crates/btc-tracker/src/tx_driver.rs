//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use algebra::{
    monoid::{self, Monoid},
    semigroup::Semigroup,
};
use bitcoin::{Amount, FeeRate, Transaction, Txid};
use bitcoind_async_client::{
    error::ClientError,
    traits::{Broadcaster, Reader},
    types::BroadcastOptions,
    Client as BitcoinClient,
};
use futures::{channel::oneshot, stream::SelectAll, FutureExt, StreamExt};
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
        self, BumpReason, CpfpContext, CpfpDisabled, CpfpFeeSource, CpfpHandle, CpfpMempool,
        CpfpStrategy, CpfpWallet,
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

/// The TxJobHeap is a map from [`Txid`]s to the corresponding [`Transaction`] and a list of
/// listeners for the results.
struct TxJobHeap(BTreeMap<Txid, TxSubscriberSet>);
impl TxJobHeap {
    /// Removes all jobs associated with a given [`Transaction`] and returns the job details.
    fn remove(&mut self, txid: &Txid) -> Option<TxSubscriberSet> {
        self.0.remove(txid)
    }
}

/// The Semigroup impl for TxJobHeap merges heaps so that all listeners are notified but the
/// representation is always minimally encoded.
impl Semigroup for TxJobHeap {
    fn merge(self, other: Self) -> Self {
        let mut a = self.0;
        let b = other.0;
        for (k, v) in b {
            match a.get_mut(&k) {
                Some(responders) => responders.extend(v),
                None => {
                    a.insert(k, v);
                }
            }
        }
        TxJobHeap(a)
    }
}

/// The Monoid impl for TxJobHeap yields a heap that contains no transactions it is trying to drive.
impl Monoid for TxJobHeap {
    fn empty() -> TxJobHeap {
        TxJobHeap(BTreeMap::new())
    }
}

impl From<TxDriveJob> for TxJobHeap {
    /// Converts a TxDriveJob into a TxJobHeap with a single job in it. Discards `cpfp` —
    /// CPFP-specific state lives in a parallel map keyed on the parent txid.
    fn from(job: TxDriveJob) -> Self {
        let mut heap = BTreeMap::new();
        heap.insert(job.tx.compute_txid(), vec![(job.condition, job.respond_on)]);
        TxJobHeap(heap)
    }
}

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

/// Per-parent CPFP state. Keyed on parent txid in the shared `CpfpEntries` map.
///
/// Holds the parent transaction (needed for re-building children on bump), its strategy, and
/// the [`CpfpHandle`] tracking the most recent child's funding inputs and package rate.
#[derive(Clone)]
struct CpfpEntry {
    parent: Transaction,
    strategy: CpfpStrategy,
    handle: CpfpHandle,
    /// True while the parent is mined but not yet buried. A dormant entry is not bumped —
    /// a confirmed parent needs no child — but it is kept, because a reorg between mined
    /// and buried puts the parent back in (or out of) the mempool, and bumping must resume
    /// then. Removal happens only at burial, when the callers' own wait conditions resolve.
    dormant: bool,
}

/// Shared CPFP state across the driver task and the spawned bump tasks. `Arc<Mutex>` so
/// reactive bump tasks (new block, timer tick) can run concurrently with the driver loop —
/// the driver task isn't blocked waiting on N×submitpackage RPCs.
type CpfpEntries = Arc<Mutex<HashMap<Txid, CpfpEntry>>>;

/// Walks every entry in `entries` and runs one `perform_bump` per entry under `reason`.
///
/// **Lock discipline.** Snapshots the keys + each entry (cloning parent/strategy/handle)
/// under a brief lock so the slow `perform_bump` call runs WITHOUT the entries mutex held.
/// On completion, re-acquires the lock to write back the updated handle, IF the entry still
/// exists (it may have been removed in the meantime, e.g. the parent confirmed). This means
/// new-job insertions and confirm-removals are never blocked by an in-flight bump batch.
///
/// Spawned as a separate tokio task by the driver's block/tick select! arms so the driver
/// returns to its select! immediately. Within this task, bumps are serial — they share the
/// wallet's `RwLock::write()` anyway, so additional intra-batch concurrency wouldn't help.
async fn bump_all_entries<W, F, P>(
    ctx: Arc<CpfpContext<W, F, P>>,
    entries: CpfpEntries,
    bridge_protocol_floor: FeeRate,
    reason: cpfp::BumpReason,
) where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    let txids: Vec<Txid> = entries.lock().await.keys().copied().collect();
    for parent_txid in txids {
        bump_one_entry(
            ctx.as_ref(),
            &entries,
            parent_txid,
            bridge_protocol_floor,
            reason,
        )
        .await;
    }
}

/// Fallback for a parent whose bare broadcast was rejected: register a CPFP entry and try to
/// carry the parent into the mempool inside a `[parent, child]` package. Returns whether the
/// package was actually submitted.
///
/// On any non-submission outcome the just-registered entry is removed again. The caller is
/// about to fail the job and drop its subscription, so the confirm-removal path in the event
/// arm could never fire for this txid — an orphaned entry would be bumped on every block and
/// tick forever, churning wallet leases for a parent that never reached the mempool.
async fn fallback_package_submit<W, F, P>(
    ctx: &CpfpContext<W, F, P>,
    entries: &CpfpEntries,
    parent: Transaction,
    strategy: CpfpStrategy,
    bridge_protocol_floor: FeeRate,
) -> bool
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    let (txid, inserted) = upsert_cpfp_entry(entries, parent, strategy).await;
    let submitted = bump_one_entry(
        ctx,
        entries,
        txid,
        bridge_protocol_floor,
        BumpReason::NewJob,
    )
    .await;
    if !submitted && inserted {
        // The removed entry drops the lease of its last child, which frees the funding
        // inputs of a child that never reached a mempool.
        //
        // Remove only an entry that this call inserted. A pre-existing entry belongs to
        // an earlier job that still waits on it, and its reactive bumps continue.
        entries.lock().await.remove(&txid);
    }
    submitted
}

/// Bare (non-package) resubmission of an evicted transaction, preserving the pre-CPFP
/// driver behaviour for parents without a CPFP entry and as the fallback when a bump
/// declines to submit.
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

/// Runs one `perform_bump` for the entry at `parent_txid`, writing the updated handle back
/// if the entry still exists. Returns whether a `[parent, child]` package was actually
/// submitted. No-op returning `false` when the entry has vanished (parent confirmed and was
/// removed between the caller's look-up and ours).
///
/// The handle is written back **even when the bump fails**: `perform_bump` records the
/// child's funding inputs as soon as the wallet leases them, and dropping that update on
/// the floor would strand the leases (see the lease-recording note on
/// [`cpfp::perform_bump`]).
///
/// Shared by the batch walker, the eviction arm, and the new-job registration, so every
/// path bumps with identical snapshot / write-back discipline. The batch and eviction
/// callers serialize through the driver's single `active_bump_task` slot. The new-job
/// caller does not share that slot, so it gates itself on the slot's state before it
/// bumps: two concurrent bumps of one entry snapshot the same handle, and the later
/// write-back clobbers the lease that the earlier one took.
async fn bump_one_entry<W, F, P>(
    ctx: &CpfpContext<W, F, P>,
    entries: &CpfpEntries,
    parent_txid: Txid,
    bridge_protocol_floor: FeeRate,
    reason: cpfp::BumpReason,
) -> bool
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    // Snapshot under a brief lock; the slow bump runs without the entries mutex held.
    let snapshot = entries
        .lock()
        .await
        .get(&parent_txid)
        .filter(|e| !e.dormant)
        .map(|e| (e.parent.clone(), e.strategy.clone(), e.handle.clone()));
    let Some((parent, strategy, mut handle)) = snapshot else {
        return false; // entry removed, or dormant (parent mined; awaiting burial)
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
    // Write the updated handle back if the entry still exists and is awake. Two other
    // cases exist, and both mean an event arm settled this parent during the bump:
    //
    // - Entry gone: the parent was buried and the removal dropped the map handle.
    // - Entry dormant: the parent was mined, and the Mined arm cleared the lease of the map handle.
    //
    // Neither case needs a release call. The local handle drops at the end of this function.
    // When this bump built a child, the local handle owns the only clone of that lease, and
    // the drop frees the inputs. When it did not, the local handle holds a clone of the
    // lease that the map still owns, and the drop frees nothing.
    match entries.lock().await.get_mut(&parent_txid) {
        Some(entry) if !entry.dormant => entry.handle = handle,
        _ => {}
    }
    match result {
        Ok(true) => {
            debug!(%parent_txid, ?reason, "CPFP bump submitted");
            true
        }
        Ok(false) => {
            // Target at or below floor; expected in a quiet mempool.
            false
        }
        Err(e) if e.is_replacement_contention() => {
            // Another watchtower holds this shared anchor and our child does not pay enough
            // more to displace it. Expected on every trigger until the parent confirms.
            debug!(%parent_txid, ?reason, "CPFP bump lost the race for a shared anchor");
            false
        }
        Err(e) => {
            warn!(%parent_txid, error = %e, ?reason, "CPFP bump failed; will retry on next trigger");
            false
        }
    }
}

/// Inserts (or refreshes) a [`CpfpEntry`] for `parent`, then runs one initial `NewJob` bump
/// through [`bump_one_entry`], sharing its snapshot / write-back discipline. Used by the
/// new-job arm in three places: after a successful bare broadcast, when the parent is
/// already in the mempool at job arrival, and as a fallback when bare broadcast fails (so a
/// properly-priced child can carry an underpriced parent in via `submitpackage`).
///
/// The insert is get-or-create. A duplicate drive job for a parent that already has an
/// entry keeps the live handle and only refreshes the parent and strategy. The duty retry
/// tick re-emits publishes while the SM waits for burial, and the handle's
/// `last_child_lease` is the only record of the wallet leases. The insert also runs
/// *before* the bump. The reverse order (bump into a private entry, insert after) opens a
/// write-back race: a concurrent batch bump of the same parent leases fresh funding and
/// records it in the map, and a late insert then overwrites that record with a stale
/// handle. The leases are lost.
///
/// Returns whether a `[parent, child]` package was actually submitted (relevant for the
/// fallback caller — the parent is then in the mempool). Failures are logged inside
/// [`bump_one_entry`]; reactive bumps on block / tick / eviction retry regardless.
async fn register_cpfp_entry_and_bump<W, F, P>(
    ctx: &CpfpContext<W, F, P>,
    entries: &CpfpEntries,
    parent: Transaction,
    strategy: CpfpStrategy,
    bridge_protocol_floor: FeeRate,
) -> bool
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    let (txid, _) = upsert_cpfp_entry(entries, parent, strategy).await;
    bump_one_entry(
        ctx,
        entries,
        txid,
        bridge_protocol_floor,
        cpfp::BumpReason::NewJob,
    )
    .await
}

/// Inserts a [`CpfpEntry`] for `parent`, or refreshes the parent and strategy of an
/// existing entry while its handle (the lease record) stays live. Returns the parent txid
/// and whether the call inserted a new entry.
async fn upsert_cpfp_entry(
    entries: &CpfpEntries,
    parent: Transaction,
    strategy: CpfpStrategy,
) -> (Txid, bool) {
    let txid = parent.compute_txid();
    let mut entries = entries.lock().await;
    let inserted = match entries.get_mut(&txid) {
        Some(existing) => {
            existing.parent = parent;
            existing.strategy = strategy;
            false
        }
        None => {
            entries.insert(
                txid,
                CpfpEntry {
                    parent,
                    strategy,
                    handle: CpfpHandle::default(),
                    dormant: false,
                },
            );
            true
        }
    };
    (txid, inserted)
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
            let mut active_tx_subs = SelectAll::<Subscription<TxEvent>>::new();
            let mut active_jobs = TxJobHeap::empty();
            // CPFP state for active parents, keyed on parent txid. Populated when a job
            // arrives with `Some(cpfp_strategy)`, cleared when the parent confirms (the
            // mined/buried branch below). `Arc<Mutex<>>` so spawned bump tasks can take
            // a brief lock without blocking the driver loop on long bump RPCs (S1 fix —
            // see `bump_all_entries` for the lock discipline).
            let cpfp_entries: CpfpEntries = Arc::new(Mutex::new(HashMap::new()));
            // Handle of the currently in-flight `bump_all_entries` task, if any. New
            // block/tick triggers skip spawning if the previous batch hasn't finished —
            // prevents fan-out pile-up under sustained slowness (slow RPC, contended wallet
            // lock) which would otherwise queue stale-snapshot tasks behind each other and
            // re-trigger benign-but-noisy `release(prior)` warnings. The next tick will
            // pick up freshly-evolved state once the previous task drains.
            let mut active_bump_task: Option<JoinHandle<()>> = None;
            // Timer that fires every `bump_check_interval`. Note the cost model: tick is a
            // reactive `BumpReason`, so entries whose target sits ABOVE the protocol floor
            // are fully rebuilt every tick (wallet build + sign + submitpackage that either
            // dedups against the live child or bounces off the BIP-125 incremental-fee rule)
            // — deliberate, because a silently-evicted child is invisible and the tick is
            // what revives it. The walk is only cheap in the quiet-mempool steady state,
            // where the floor / parent-fee baseline skips return `Ok(false)` before any
            // wallet call.
            let mut bump_tick = tokio::time::interval(bump_check_interval);
            // `Interval::tick` fires immediately on first call. Burn it so the first effective
            // bump tick is one full interval after construction.
            bump_tick.tick().await;
            loop {
                select! {
                    Some(job) = new_jobs_receiver_stream.next().fuse() => {
                        let rawtx_filter = job.tx.clone();
                        let rawtx_rpc_client = job.tx.clone();
                        let txid = job.tx.compute_txid();
                        let tx_sub = zmq_client.subscribe_transactions(
                            move |tx| tx == &rawtx_filter
                        ).await;

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
                            } else {
                                // if the condition is not met, we still need to add the job
                                // to the active jobs so that we can notify it later.
                                // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2687>
                                // Handle the race where the relevant event may already have
                                // happened before the subscription is established.
                                active_tx_subs.push(tx_sub);
                                let job_parent = job.tx.clone();
                                let job_cpfp = job.cpfp.clone();
                                active_jobs = active_jobs.merge(job.into());

                                // Register CPFP for an already-resident parent. Without
                                // this, parents broadcast in a prior incarnation that are
                                // still in the mempool when the driver comes back up would
                                // never be re-bumped on block / tick / eviction events.
                                // The first bump runs here too so a deeply-underpriced
                                // resident parent gets a fresh package immediately.
                                if let (Some(ctx), Some(strategy)) = (cpfp_ctx.as_ref(), job_cpfp) {
                                    // The eager bump must not run next to an in-flight
                                    // batch or eviction bump: two concurrent bumps of one
                                    // entry snapshot the same handle, and the later
                                    // write-back clobbers the earlier one's lease record.
                                    // The entry registers either way; the next trigger
                                    // bumps it. Failures are logged inside
                                    // `bump_one_entry`.
                                    if active_bump_task.as_ref().is_some_and(|h| !h.is_finished()) {
                                        let (registered_txid, _) =
                                            upsert_cpfp_entry(&cpfp_entries, job_parent, strategy)
                                                .await;
                                        debug!(%registered_txid, "bump slot busy; CPFP entry registered without an eager bump");
                                    } else {
                                        register_cpfp_entry_and_bump(
                                            ctx.as_ref(),
                                            &cpfp_entries,
                                            job_parent,
                                            strategy,
                                            bridge_protocol_floor,
                                        )
                                        .await;
                                    }
                                }
                            }

                            continue;
                        }

                        let options = broadcast_options(&rawtx_rpc_client);
                        match rpc_client.send_raw_transaction(&rawtx_rpc_client, options).await {
                            Ok(txid) => {
                                info!(%txid, "broadcasted transaction successfully");
                                // only add subscriptions and jobs if the transaction was
                                // broadcasted successfully
                                // NOTE: (@Rajil1213) this code is duplicated here. An alternative
                                // is to add the subscription at the top and then remove them if the submission errors
                                // but removing a subscription from a `SelectAll` is not straightforward.
                                active_tx_subs.push(tx_sub);
                                let job_parent = job.tx.clone();
                                let job_cpfp = job.cpfp.clone();
                                active_jobs = active_jobs.merge(job.into());

                                // Eager initial bump: if CPFP is configured and the fee
                                // source's target is above the protocol floor, build and
                                // submit a CPFP child as a package right now. Targets at or
                                // below the floor mean the presigned parent's own rate is
                                // sufficient; the helper's `perform_bump` skips internally.
                                if let (Some(ctx), Some(strategy)) = (cpfp_ctx.as_ref(), job_cpfp) {
                                    // The eager bump must not run next to an in-flight
                                    // batch or eviction bump: two concurrent bumps of one
                                    // entry snapshot the same handle, and the later
                                    // write-back clobbers the earlier one's lease record.
                                    // The entry registers either way; the next trigger
                                    // bumps it. Failures are logged inside
                                    // `bump_one_entry`.
                                    if active_bump_task.as_ref().is_some_and(|h| !h.is_finished()) {
                                        let (registered_txid, _) =
                                            upsert_cpfp_entry(&cpfp_entries, job_parent, strategy)
                                                .await;
                                        debug!(%registered_txid, "bump slot busy; CPFP entry registered without an eager bump");
                                    } else {
                                        register_cpfp_entry_and_bump(
                                            ctx.as_ref(),
                                            &cpfp_entries,
                                            job_parent,
                                            strategy,
                                            bridge_protocol_floor,
                                        )
                                        .await;
                                    }
                                }
                            },
                            Err(err) => {
                                // Bare broadcast failed. Most commonly the parent's own fee
                                // rate is below the mempool's minimum and a CPFP child can
                                // carry it in via `submitpackage` (package validation is
                                // more lenient than single-tx acceptance). If CPFP is
                                // configured, try that fallback before surfacing the error.
                                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2689>
                                // Distinguish invalid transactions and notify the job
                                // submitter directly instead of attempting fee bumping.
                                let job_parent = job.tx.clone();
                                let job_cpfp = job.cpfp.clone();
                                let pkg_submitted = if let (Some(ctx), Some(strategy)) =
                                    (cpfp_ctx.as_ref(), job_cpfp)
                                {
                                    warn!(%txid, %err, "bare broadcast failed; attempting CPFP package fallback");
                                    fallback_package_submit(
                                        ctx.as_ref(),
                                        &cpfp_entries,
                                        job_parent,
                                        strategy,
                                        bridge_protocol_floor,
                                    )
                                    .await
                                } else {
                                    false
                                };

                                if pkg_submitted {
                                    info!(%txid, "parent reached mempool via CPFP package fallback");
                                    active_tx_subs.push(tx_sub);
                                    active_jobs = active_jobs.merge(job.into());
                                } else {
                                    // `fallback_package_submit` has already removed any entry
                                    // it registered — nothing here can observe this parent
                                    // confirming once the job is failed.
                                    error!(%txid, tx=?rawtx_rpc_client, %err, "could not submit transaction");
                                    // send feedback to the job submitter
                                    if job.respond_on.send(Err(DriveErr::PublishFailed(err))).is_err() {
                                        error!("could not send error response to job submitter");
                                    }
                                }
                            }
                        }
                    }
                    Some(event) = active_tx_subs.next().fuse() => {
                        let evicted_txid = event.rawtx.compute_txid();
                        match event.status {
                            TxStatus::Unknown => {
                                // Transaction has been evicted. If this parent has CPFP
                                // enabled, rebuild the child at the current fee target and
                                // re-submit as a package — that's the canonical bump path on
                                // mempool eviction. Otherwise fall back to bare resubmission
                                // (legacy behaviour preserved for non-CPFP callers).
                                let has_cpfp_entry = cpfp_ctx.is_some() && {
                                    let mut entries = cpfp_entries.lock().await;
                                    match entries.get_mut(&evicted_txid) {
                                        Some(entry) => {
                                            // A dormant entry means the parent was mined. An
                                            // eviction event for it means a reorg dropped
                                            // the parent from its block and from the
                                            // mempool. That is the situation the bumps
                                            // exist for. Wake the entry.
                                            if entry.dormant {
                                                info!(%evicted_txid, "mined parent evicted after a reorg; resuming CPFP bumps");
                                                entry.dormant = false;
                                            }
                                            true
                                        }
                                        None => false,
                                    }
                                };
                                if let (Some(ctx), true) = (cpfp_ctx.as_ref(), has_cpfp_entry) {
                                    // The eviction bump shares the block/tick arms' single
                                    // in-flight slot. Two concurrent bumps of one entry would
                                    // snapshot the same handle and the later write-back would
                                    // clobber the lease that the earlier one took,
                                    // stranding the loser's wallet leases — the exact failure
                                    // `perform_bump`'s eager lease recording exists to
                                    // prevent. Spawning (rather than bumping inline) also
                                    // keeps the driver select loop responsive through the
                                    // build + sign + submitpackage round-trip.
                                    if active_bump_task.as_ref().is_some_and(|h| !h.is_finished()) {
                                        // The in-flight batch snapshotted its txid list at
                                        // its start. It can miss this entry (registered
                                        // after the snapshot) or it can have walked past
                                        // this txid already. Neither case resubmits the
                                        // evicted parent. Resubmit the bare parent now; the
                                        // next block or tick rebuilds the child on top.
                                        debug!(%evicted_txid, "bump slot busy; resubmitting evicted parent bare until the next trigger");
                                        resubmit_bare(&rpc_client, &event.rawtx, evicted_txid).await;
                                    } else {
                                        let ctx = ctx.clone();
                                        let entries = cpfp_entries.clone();
                                        let floor = bridge_protocol_floor;
                                        let rawtx = event.rawtx.clone();
                                        let rpc_client = rpc_client.clone();
                                        active_bump_task = Some(tokio::spawn(async move {
                                            let submitted = bump_one_entry(
                                                ctx.as_ref(),
                                                &entries,
                                                evicted_txid,
                                                floor,
                                                BumpReason::ParentEvicted,
                                            )
                                            .await;
                                            if !submitted {
                                                // Bump declined (target at floor) or failed;
                                                // keep the legacy behaviour of at least
                                                // putting the bare parent back.
                                                resubmit_bare(&rpc_client, &rawtx, evicted_txid).await;
                                            }
                                        }));
                                    }
                                } else {
                                    resubmit_bare(&rpc_client, &event.rawtx, evicted_txid).await;
                                }
                            }
                            _ => {
                                let txid = event.rawtx.compute_txid();
                                let listeners = active_jobs.remove(&txid);
                                let leftovers = monoid::concat(listeners
                                    .into_iter()
                                    .flat_map(Vec::into_iter)
                                    .filter_map(|(condition, response)| {
                                        if condition(&event.status) {
                                            let _ = response.send(Ok(()));
                                            None
                                        } else {
                                            Some(
                                                TxJobHeap(
                                                    BTreeMap::from([
                                                        (txid, vec![(condition, response)])
                                                    ])
                                                )
                                            )
                                        }
                                    }));
                                active_jobs = active_jobs.merge(leftovers);
                                // CPFP lifecycle against confirmation depth:
                                //
                                // - Mined: stop the bumps (a confirmed parent needs no
                                //   child), drop the lease of the child, and keep the
                                //   entry dormant. Each production caller waits for
                                //   burial. A reorg between mined and buried returns the
                                //   parent to the mempool (`Mempool`) or evicts it
                                //   (`Unknown`), and the bumps must resume then. A removal
                                //   here makes the parent unbumpable for the rest of the
                                //   wait: the eviction arm falls back to a bare resubmit
                                //   of a floor-rate parent, no mempool accepts it under
                                //   fee pressure, and the duty never completes.
                                // - Mempool: the reorg case. Wake the entry.
                                // - Buried: final. Remove the entry, which drops any lease
                                //   that the Mined arm did not already drop.
                                //
                                // If the parent confirmed through a competitor's child,
                                // the drop frees our dead child's funding. If our own
                                // child confirmed, its funding is spent on chain — see the
                                // release note in `perform_bump` step 4.5 for the bounded
                                // side effect. A woken entry starts from an empty handle
                                // and takes a fresh lease on its next bump.
                                match event.status {
                                    TxStatus::Mined { .. } => {
                                        let mut entries = cpfp_entries.lock().await;
                                        if let Some(entry) = entries.get_mut(&txid) {
                                            entry.dormant = true;
                                            entry.handle = CpfpHandle::default();
                                        }
                                    }
                                    TxStatus::Mempool => {
                                        if let Some(entry) = cpfp_entries.lock().await.get_mut(&txid) {
                                            if entry.dormant {
                                                info!(%txid, "parent reorged back into the mempool; resuming CPFP bumps");
                                                entry.dormant = false;
                                            }
                                        }
                                    }
                                    TxStatus::Buried { .. } => {
                                        cpfp_entries.lock().await.remove(&txid);
                                    }
                                    TxStatus::Unknown => {}
                                }
                            }
                        }

                    }
                    _block = block_subscription.next().fuse() => {
                        // On each new block, spawn a task that walks every CPFP parent and
                        // runs a bump. Spawned (not inline) so the driver returns to its
                        // select! immediately — new jobs and ZMQ events aren't blocked even
                        // if there are many entries or the bumps stall on a slow RPC. See
                        // `bump_all_entries` for the lock-discipline details, and
                        // `active_bump_task` above for the fan-out guard rationale.
                        if let Some(ctx) = cpfp_ctx.as_ref() {
                            if active_bump_task.as_ref().is_some_and(|h| !h.is_finished()) {
                                debug!("skipping new-block bump: previous bump batch still running");
                            } else {
                                let ctx = ctx.clone();
                                let entries = cpfp_entries.clone();
                                let floor = bridge_protocol_floor;
                                active_bump_task = Some(tokio::spawn(async move {
                                    bump_all_entries(ctx, entries, floor, BumpReason::NewBlock).await;
                                }));
                            }
                        }
                    }
                    _ = bump_tick.tick().fuse() => {
                        // Periodic timer-driven bump — same shape as the new-block arm, with
                        // the same in-flight guard.
                        if let Some(ctx) = cpfp_ctx.as_ref() {
                            if active_bump_task.as_ref().is_some_and(|h| !h.is_finished()) {
                                debug!("skipping tick bump: previous bump batch still running");
                            } else {
                                let ctx = ctx.clone();
                                let entries = cpfp_entries.clone();
                                let floor = bridge_protocol_floor;
                                active_bump_task = Some(tokio::spawn(async move {
                                    bump_all_entries(ctx, entries, floor, BumpReason::Tick).await;
                                }));
                            }
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
    /// Aborts the main driver task. Note that any in-flight `bump_all_entries` task spawned
    /// by the block / tick arms is **detached** — its `JoinHandle` was stored in the driver
    /// task's local `active_bump_task` slot, which is dropped (not awaited) along with the
    /// driver task itself. The detached bump task continues running on the runtime until it
    /// finishes its current pass over `cpfp_entries`. At process shutdown the runtime tears
    /// the task down regardless; for graceful in-process restart of `TxDriver`, a brief race
    /// with the previous instance's bump task is possible (each call holds the wallet lock
    /// per-bump, releases between, and the entries map is per-`TxDriver` so the old task
    /// operates on its own snapshot). Acceptable for current call patterns; if mid-process
    /// `TxDriver` lifecycle ever becomes load-bearing, expose a `shutdown(self)` that awaits
    /// the active bump task before aborting the driver task.
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

    use bitcoin::{Amount, OutPoint};

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
            mempool: Arc::new(submitter),
        }
    }

    /// A dormant entry (parent mined, burial pending) is not bumped. The wallet and the
    /// mempool must not be called: a confirmed parent needs no child. The same entry with
    /// `dormant = false` submits, so the skip is the only difference under test.
    #[tokio::test]
    async fn bump_one_entry_skips_dormant_entries() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let funding = vec![OutPoint {
            txid: parent_txid,
            vout: 7,
        }];
        let make_entry = |dormant: bool| CpfpEntry {
            parent: parent.clone(),
            strategy: anchor_strategy(key),
            handle: CpfpHandle::default(),
            dormant,
        };

        for (dormant, expect_submit) in [(true, false), (false, true)] {
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
                mempool: submitter.clone(),
            };
            let entries: CpfpEntries = Arc::new(Mutex::new(HashMap::from([(
                parent_txid,
                make_entry(dormant),
            )])));
            let submitted = bump_one_entry(
                &ctx,
                &entries,
                parent_txid,
                crate::cpfp::tests::PROTOCOL_FLOOR,
                BumpReason::Tick,
            )
            .await;
            assert_eq!(submitted, expect_submit, "dormant = {dormant}");
            assert_eq!(
                submitter.captured.lock().unwrap().len(),
                usize::from(expect_submit),
                "dormant = {dormant}"
            );
        }
    }

    /// Even a failed bump must land its handle back in the entries map: `perform_bump` records
    /// the freshly-leased funding inputs on the handle as soon as the wallet returns, and the
    /// next bump can only release them if that update survives into the map.
    #[tokio::test]
    async fn bump_one_entry_writes_handle_back_on_submit_failure() {
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
        let entries: CpfpEntries = Arc::new(Mutex::new(HashMap::from([(
            parent_txid,
            CpfpEntry {
                parent: parent.clone(),
                strategy: anchor_strategy(key),
                handle: CpfpHandle::default(),
                dormant: false,
            },
        )])));

        let submitted = bump_one_entry(
            &ctx,
            &entries,
            parent_txid,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
        )
        .await;

        assert!(!submitted, "rejected package must not report submission");
        let map = entries.lock().await;
        assert_eq!(
            map[&parent_txid]
                .handle
                .last_child_lease
                .as_deref()
                .expect("the entry must hold a lease")
                .outpoints(),
            funding,
            "leased funding inputs must be written back even though submission failed"
        );
        assert!(
            map[&parent_txid].handle.last_child_txid.is_none(),
            "nothing reached the mempool, so the child txid must not advance"
        );
    }

    /// A vanished entry (parent confirmed between look-up and bump) is a quiet no-op — in
    /// particular the wallet must never be asked to fund a child for it.
    #[tokio::test]
    async fn bump_one_entry_is_noop_when_entry_vanished() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let ctx = test_ctx(
            FakeWallet::failing("wallet must not be called for a vanished entry"),
            FakeSubmitter::failing("submitter must not be called either"),
        );
        let entries: CpfpEntries = Arc::new(Mutex::new(HashMap::new()));

        let submitted = bump_one_entry(
            &ctx,
            &entries,
            parent.compute_txid(),
            PROTOCOL_FLOOR,
            BumpReason::NewBlock,
        )
        .await;

        assert!(!submitted);
        assert!(entries.lock().await.is_empty());
    }

    /// The bare-broadcast fallback must not leave an orphaned entry behind when the package
    /// submission fails too: the caller is about to fail the job and drop its subscription, so
    /// nothing could ever remove the entry, and it would be re-bumped forever.
    #[tokio::test]
    async fn failed_fallback_leaves_no_orphan_entry() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0, key);
        let ctx = test_ctx(
            FakeWallet::returning(
                psbt,
                vec![OutPoint {
                    txid: parent.compute_txid(),
                    vout: 7,
                }],
            ),
            FakeSubmitter::failing("package-not-valid"),
        );
        let entries: CpfpEntries = Arc::new(Mutex::new(HashMap::new()));

        let submitted = fallback_package_submit(
            &ctx,
            &entries,
            parent.clone(),
            anchor_strategy(key),
            PROTOCOL_FLOOR,
        )
        .await;

        assert!(!submitted);
        assert!(
            entries.lock().await.is_empty(),
            "failed fallback must remove the entry it registered"
        );
    }

    /// The successful fallback keeps its entry — the job survives, its subscription is pushed,
    /// and the confirm-removal path owns the entry from here.
    #[tokio::test]
    async fn successful_fallback_keeps_entry_for_future_bumps() {
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
            FakeSubmitter::ok(),
        );
        let entries: CpfpEntries = Arc::new(Mutex::new(HashMap::new()));

        let submitted =
            fallback_package_submit(&ctx, &entries, parent, anchor_strategy(key), PROTOCOL_FLOOR)
                .await;

        assert!(submitted);
        let map = entries.lock().await;
        assert_eq!(
            map[&parent_txid]
                .handle
                .last_child_lease
                .as_deref()
                .expect("the entry must hold a lease")
                .outpoints(),
            funding,
            "the surviving entry must carry the bump's lease state"
        );
    }
}
