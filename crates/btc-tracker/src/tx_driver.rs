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
use bitcoin::{FeeRate, Transaction, Txid};
use bitcoind_async_client::{
    error::ClientError,
    traits::{Broadcaster, Reader},
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
        self, BumpReason, CpfpContext, CpfpDisabled, CpfpFeeSource, CpfpHandle,
        CpfpPackageSubmitter, CpfpStrategy, CpfpWallet,
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
    P: CpfpPackageSubmitter + 'static,
{
    let txids: Vec<Txid> = entries.lock().await.keys().copied().collect();
    for parent_txid in txids {
        let snapshot = entries
            .lock()
            .await
            .get(&parent_txid)
            .map(|e| (e.parent.clone(), e.strategy, e.handle.clone()));
        let Some((parent, strategy, mut handle)) = snapshot else {
            continue; // entry confirmed / removed since we snapshotted keys
        };
        match cpfp::perform_bump(
            ctx.as_ref(),
            &parent,
            strategy,
            &mut handle,
            bridge_protocol_floor,
            reason,
        )
        .await
        {
            Ok(true) => debug!(%parent_txid, ?reason, "CPFP bump submitted"),
            Ok(false) => {
                // Target at or below floor; expected in a quiet mempool.
            }
            Err(e) => {
                warn!(%parent_txid, error = %e, ?reason, "CPFP bump failed; will retry on next trigger")
            }
        }
        // Write back the updated handle if the entry still exists.
        if let Some(entry) = entries.lock().await.get_mut(&parent_txid) {
            entry.handle = handle;
        }
    }
}

/// System for driving a signed transaction to confirmation.
#[derive(Debug)]
pub struct TxDriver {
    new_jobs_sender: UnboundedSender<TxDriveJob>,
    driver: JoinHandle<()>,
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
        P: CpfpPackageSubmitter + 'static,
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
            // Timer that fires every `bump_check_interval`. Walking the cpfp_entries map and
            // calling `perform_bump` on each is cheap when the cached rate hasn't moved (skip
            // logic returns Ok(false)), so the driver can poll aggressively without straining
            // the wallet lock under steady-state.
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
                                active_jobs = active_jobs.merge(job.into());
                            }

                            continue;
                        }

                        match rpc_client.send_raw_transaction(&rawtx_rpc_client).await {
                            Ok(txid) => {
                                info!(%txid, "broadcasted transaction successfully");
                                // only add subscriptions and jobs if the transaction was
                                // broadcasted successfully
                                // NOTE: (@Rajil1213) this code is duplicated here. An alternative
                                // is to add the subscription at the top and then remove them if the submission errors
                                // but removing a subscription from a `SelectAll` is not straightforward.
                                active_tx_subs.push(tx_sub);
                                let job_parent = job.tx.clone();
                                let job_cpfp = job.cpfp;
                                active_jobs = active_jobs.merge(job.into());

                                // Eager initial bump: if CPFP is configured and the fee
                                // source's target is above the protocol floor, build and
                                // submit a CPFP child as a package right now. Per design
                                // decision Q4 (see STR-3439-PLAN.md): targets at or below
                                // the floor mean the presigned parent's own rate is
                                // sufficient; skip the child.
                                if let (Some(ctx), Some(strategy)) = (cpfp_ctx.as_ref(), job_cpfp) {
                                    let mut entry = CpfpEntry {
                                        parent: job_parent.clone(),
                                        strategy,
                                        handle: CpfpHandle::default(),
                                    };
                                    if let Err(e) = cpfp::perform_bump(
                                        ctx.as_ref(),
                                        &entry.parent,
                                        entry.strategy,
                                        &mut entry.handle,
                                        bridge_protocol_floor,
                                        BumpReason::NewJob,
                                    )
                                    .await
                                    {
                                        warn!(%txid, error = %e, "initial CPFP bump failed; will retry on next trigger");
                                    }
                                    cpfp_entries.lock().await.insert(txid, entry);
                                }
                            },
                            Err(err) => {
                                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2688>
                                // If we have not hit the mempool purge rate, CPFP using the
                                // anchor from the start and retry as a package.
                                //
                                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2689>
                                // Distinguish invalid transactions and notify the job submitter
                                // instead of treating them like fee-bumping work.
                                // For now, we just inform the caller until we add fee-bumping
                                // support.
                                error!(%txid, tx=?rawtx_rpc_client, %err, "could not submit transaction");
                                // send feedback to the job submitter
                                if job.respond_on.send(Err(DriveErr::PublishFailed(err))).is_err() {
                                    error!("could not send error response to job submitter");
                                }
                            }
                        }
                    }
                    Some(event) = active_tx_subs.next().fuse() => {
                        let evicted_txid = event.rawtx.compute_txid();
                        match event.status {
                            TxStatus::Unknown => {
                                // Transaction has been evicted. If this parent has CPFP enabled,
                                // rebuild the child at the current fee target and re-submit as
                                // a package — that's the canonical bump path on mempool
                                // eviction. Otherwise fall back to bare resubmission (legacy
                                // behaviour preserved for non-CPFP callers).
                                let did_cpfp = if let Some(ctx) = cpfp_ctx.as_ref() {
                                    // Snapshot the entry under a brief lock; the slow bump
                                    // runs without the entries mutex held. On completion,
                                    // re-acquire briefly to write back the updated handle.
                                    let snapshot = cpfp_entries
                                        .lock()
                                        .await
                                        .get(&evicted_txid)
                                        .map(|e| (e.parent.clone(), e.strategy, e.handle.clone()));
                                    if let Some((parent, strategy, mut handle)) = snapshot {
                                        let bump_result = cpfp::perform_bump(
                                            ctx.as_ref(),
                                            &parent,
                                            strategy,
                                            &mut handle,
                                            bridge_protocol_floor,
                                            BumpReason::ParentEvicted,
                                        )
                                        .await;
                                        if let Some(entry) = cpfp_entries.lock().await.get_mut(&evicted_txid) {
                                            entry.handle = handle;
                                        }
                                        match bump_result {
                                            Ok(true) => {
                                                info!(%evicted_txid, "CPFP bump submitted on mempool eviction");
                                                true
                                            }
                                            Ok(false) => false,
                                            Err(e) => {
                                                warn!(%evicted_txid, error = %e, "CPFP bump failed on eviction; falling back to bare resubmit");
                                                false
                                            }
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                };

                                if !did_cpfp {
                                    match rpc_client.send_raw_transaction(&event.rawtx).await {
                                        Ok(txid) => {
                                            info!(%txid, "resubmitted transaction successfully");
                                        }
                                        Err(err) => {
                                            error!(%evicted_txid, %err, "could not resubmit transaction");
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
                                // If this event represents confirmation (mined/buried), the
                                // parent has landed on chain — drop its CPFP state so we stop
                                // bumping. Mempool events leave the entry alone.
                                if matches!(event.status, TxStatus::Mined { .. } | TxStatus::Buried { .. }) {
                                    cpfp_entries.lock().await.remove(&txid);
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
mod e2e_tests {
    use std::{collections::VecDeque, path::PathBuf, sync::Arc};

    use algebra::predicate;
    use bitcoin::{Amount, Block};
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
            .drive(signed.clone(), predicate::eq(TxStatus::Mempool))
            .await?;
        info!("transaction appeared in mempool");

        Ok(())
    }
}
