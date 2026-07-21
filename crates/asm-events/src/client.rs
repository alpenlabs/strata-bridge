//! ASM event feed client.
//!
//! Expectations:
//! - ASM RPC tracks the same chain and has already ingested blocks before we request
//!   `get_assignments(block_hash)`. We treat the BTC block notification as a signal that ASM should
//!   already have executed that block.
//! - If ASM is briefly behind, retries are expected to bridge the gap. The fetcher assumes eventual
//!   availability and keeps the main loop non-blocking.
//! - If ASM is persistently behind due to configuration/connectivity, requests can keep failing for
//!   "new" blocks. This is not expected behavior, but it can happen and should show up as repeated
//!   retries/failures in logs/metrics.
//! - If ASM follows a different fork, the notified block hash may not exist on ASM. This can
//!   surface as "block not found" responses; we currently log/skip after retries.
// TODO: <https://alpenlabs.atlassian.net/browse/STR-2667>
// Explicitly detect lag vs. fork divergence and surface a clear health signal.

use std::{fmt, marker::PhantomData, sync::Arc};

use algebra::retry::{Strategy, retry_with};
use bitcoin::BlockHash;
use btc_tracker::event::{BlockEvent, BlockStatus};
use futures::StreamExt;
use jsonrpsee::http_client::HttpClient;
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_asm_proto_bridge_v1_types::SafeHarbour;
use strata_asm_rpc::traits::{AsmControlApiClient, AsmStateApiClient};
use strata_bridge_primitives::subscription::Subscription;
use strata_btc_types::L1BlockIdBitcoinExt;
use thiserror::Error;
use tokio::{
    sync::{Mutex, mpsc, watch},
    task::{self, JoinHandle},
    time,
};
use tracing::{debug, error, info, warn};

use crate::{config::AsmRpcConfig, event::AsmState};

/// Marker type indicating the feed is not attached to a block stream yet.
#[derive(Debug)]
pub struct Detached;

/// Marker type indicating the feed is attached to a block stream and subscriptions are available.
#[derive(Debug)]
pub struct Attached;

/// ASM event feed, providing per-buried-block assignment and safe-harbour state updates.
#[derive(Debug, Clone)]
pub struct AsmEventFeed<State = Detached> {
    cfg: AsmRpcConfig,
    client: HttpClient,
    subscribers: Arc<Mutex<Vec<mpsc::UnboundedSender<AsmState>>>>,
    thread_handle: Option<Arc<JoinHandle<()>>>,
    health_observer: Option<HealthObserver>,
    _state: PhantomData<State>,
}

/// Health events emitted by the ASM state feed.
#[derive(Debug, Clone, Copy)]
pub enum AsmFeedHealthEvent {
    /// Assignments were fetched successfully for a buried block.
    AssignmentsFetched,

    /// Assignment fetching exhausted all retries for a buried block.
    AssignmentsFetchFailed,

    /// Safe-harbour state was fetched successfully from the ASM tip.
    SafeHarbourFetched,

    /// Safe-harbour fetching exhausted all retries; the flag is delivered as unknown this cycle.
    SafeHarbourFetchFailed,
}

#[derive(Clone)]
struct HealthObserver(Arc<dyn Fn(AsmFeedHealthEvent) + Send + Sync>);

impl HealthObserver {
    fn observe(&self, event: AsmFeedHealthEvent) {
        (self.0)(event);
    }
}

impl fmt::Debug for HealthObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HealthObserver")
            .field(&"<callback>")
            .finish()
    }
}

impl<State> Drop for AsmEventFeed<State> {
    fn drop(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            handle.abort();
        }
    }
}

impl AsmEventFeed<Detached> {
    /// Creates a new ASM event feed.
    pub fn new(client: HttpClient, cfg: AsmRpcConfig) -> AsmEventFeed<Detached> {
        AsmEventFeed {
            cfg,
            client,
            subscribers: Arc::new(Mutex::new(Vec::new())),
            thread_handle: None,
            health_observer: None,
            _state: PhantomData,
        }
    }

    /// Attaches the ASM feed to a btc-tracker block subscription and starts workers.
    ///
    /// This spawns two background tasks:
    /// - A block forwarder that forwards buried block notifications without blocking
    /// - An ASM state fetcher that queries ASM RPC (assignments at the buried block, safe harbour
    ///   at the ASM tip) and fans out results to subscribers
    ///
    /// Note: this does not validate ASM RPC connectivity. The fetcher will retry failed
    /// requests and log failures.
    pub fn attach_block_stream(
        self,
        block_sub: Subscription<BlockEvent>,
    ) -> AsmEventFeed<Attached> {
        // Using watch channel (latest-value semantics) is intentional: if the fetcher is slow,
        // we want to skip to the most recent block rather than queue all intermediate blocks.
        // Assignment state is idempotent and queryable by block hash, and the safe-harbour flag
        // is monotonic, so skipping intermediate buried blocks is harmless.
        let (request_sender, request_receiver) = watch::channel(None);
        let subscribers_worker = self.subscribers.clone();
        let health_observer = self.health_observer.clone();
        let cfg = self.cfg.clone();
        let client = self.client.clone();

        let thread_handle = Arc::new(task::spawn(async move {
            let forwarder = run_block_ref_forwarder(block_sub, request_sender);
            let fetcher = run_asm_state_fetcher(
                cfg,
                client,
                request_receiver,
                subscribers_worker,
                health_observer,
            );

            tokio::join!(forwarder, fetcher);
        }));

        AsmEventFeed {
            cfg: self.cfg.clone(),
            client: self.client.clone(),
            subscribers: self.subscribers.clone(),
            thread_handle: Some(thread_handle),
            health_observer: self.health_observer.clone(),
            _state: PhantomData,
        }
    }
}

impl<State> AsmEventFeed<State> {
    /// Installs a synchronous health observer for ASM fetch success and failure.
    pub fn with_health_observer(
        mut self,
        observer: impl Fn(AsmFeedHealthEvent) + Send + Sync + 'static,
    ) -> Self {
        self.health_observer = Some(HealthObserver(Arc::new(observer)));
        self
    }
}

impl AsmEventFeed<Attached> {
    /// Subscribes to ASM state updates.
    ///
    /// Returns a subscription that will receive [`AsmState`] events for buried blocks.
    pub async fn subscribe_asm_state(&self) -> Subscription<AsmState> {
        let (send, recv) = mpsc::unbounded_channel();

        self.subscribers.lock().await.push(send);

        Subscription::from_receiver(recv)
    }
}

#[derive(Debug, Error)]
enum FetchError {
    #[error("RPC error: {0}")]
    Rpc(#[from] jsonrpsee::core::ClientError),

    #[error("Request timed out")]
    Timeout,
}

/// Forwards buried block refs to the ASM state fetcher without blocking on RPC latency.
async fn run_block_ref_forwarder(
    mut block_sub: Subscription<BlockEvent>,
    request_sender: watch::Sender<Option<BlockHash>>,
) {
    while let Some(block_event) = block_sub.next().await {
        if block_event.status != BlockStatus::Buried {
            continue;
        }

        let block_hash = block_event.block.block_hash();
        let block_height = block_event.block.bip34_block_height().unwrap_or(0);

        debug!(%block_hash, %block_height, "forwarding block hash to ASM worker");
        let _ = request_sender.send_replace(Some(block_hash));
    }

    debug!("block subscription closed; ASM forwarder exiting");
}

/// Fetches ASM state and fans it out to subscribers.
///
/// Assignments are read at the buried block (assumed already ingested by ASM; lag is handled via
/// retries) and the safe-harbour flag is read at the ASM tip for a faster emergency response. A
/// failed assignment fetch skips the cycle (as before); a failed safe-harbour fetch is best-effort
/// and delivers `safe_harbour: None` so assignment processing is never blocked by it.
async fn run_asm_state_fetcher(
    cfg: AsmRpcConfig,
    client: HttpClient,
    mut request_receiver: watch::Receiver<Option<BlockHash>>,
    subscribers: Arc<Mutex<Vec<mpsc::UnboundedSender<AsmState>>>>,
    health_observer: Option<HealthObserver>,
) {
    let mut last_processed: Option<BlockHash> = None;

    loop {
        if request_receiver.changed().await.is_err() {
            debug!("ASM request channel closed; worker exiting");
            break;
        }

        let Some(block_hash) = *request_receiver.borrow() else {
            continue;
        };

        if last_processed == Some(block_hash) {
            continue;
        }

        // Assignments are authoritative for block processing; a failed fetch skips the cycle so it
        // is retried on the next buried block.
        let assignments = match fetch_assignments_with_retry(&cfg, &client, block_hash).await {
            Ok(assignments) => {
                observe(&health_observer, AsmFeedHealthEvent::AssignmentsFetched);
                assignments
            }
            Err(err) => {
                observe(&health_observer, AsmFeedHealthEvent::AssignmentsFetchFailed);
                error!(
                    ?err,
                    %block_hash,
                    "exhausted ASM assignment retries; skipping assignment state"
                );
                continue;
            }
        };

        // Safe harbour is best-effort: a failed fetch delivers `None` (unknown this cycle) rather
        // than blocking assignment delivery. The monotonic latch and sweep backstop cover the gap.
        let safe_harbour = match fetch_safe_harbour_with_retry(&cfg, &client).await {
            Ok(safe_harbour) => {
                observe(&health_observer, AsmFeedHealthEvent::SafeHarbourFetched);
                safe_harbour
            }
            Err(err) => {
                observe(&health_observer, AsmFeedHealthEvent::SafeHarbourFetchFailed);
                warn!(?err, %block_hash, "exhausted ASM safe-harbour retries; treating as unknown");
                None
            }
        };

        last_processed = Some(block_hash);
        info!(
            %block_hash,
            num_assignments = assignments.len(),
            safe_harbour_active = safe_harbour.as_ref().is_some_and(SafeHarbour::is_activated),
            "received ASM state"
        );

        let event = AsmState {
            block_hash,
            assignments,
            safe_harbour,
        };

        let mut subs = subscribers.lock().await;
        subs.retain(|sub| sub.send(event.clone()).is_ok());
    }
}

fn observe(health_observer: &Option<HealthObserver>, event: AsmFeedHealthEvent) {
    if let Some(observer) = health_observer {
        observer.observe(event);
    }
}

fn retry_strategy(cfg: &AsmRpcConfig) -> Strategy<FetchError> {
    Strategy::exponential_backoff(
        cfg.retry_initial_delay,
        cfg.retry_max_delay,
        cfg.retry_multiplier as f64,
    )
    .with_max_retries(cfg.max_retries)
}

async fn fetch_assignments_with_retry(
    cfg: &AsmRpcConfig,
    client: &HttpClient,
    block_hash: BlockHash,
) -> Result<Vec<AssignmentEntry>, FetchError> {
    let timeout = cfg.request_timeout;
    let strategy = retry_strategy(cfg);
    let client = client.clone();
    retry_with(strategy, move || {
        let client = client.clone();
        async move {
            fetch_assignments(&client, block_hash, timeout)
                .await
                .map_err(|err| {
                    warn!(?err, %block_hash, "failed to fetch ASM assignments");
                    err
                })
        }
    })
    .await
}

async fn fetch_safe_harbour_with_retry(
    cfg: &AsmRpcConfig,
    client: &HttpClient,
) -> Result<Option<SafeHarbour>, FetchError> {
    let timeout = cfg.request_timeout;
    let strategy = retry_strategy(cfg);
    let client = client.clone();
    retry_with(strategy, move || {
        let client = client.clone();
        async move {
            fetch_safe_harbour(&client, timeout).await.map_err(|err| {
                warn!(?err, "failed to fetch ASM safe harbour");
                err
            })
        }
    })
    .await
}

async fn fetch_assignments(
    client: &HttpClient,
    block_hash: BlockHash,
    timeout: time::Duration,
) -> Result<Vec<AssignmentEntry>, FetchError> {
    match time::timeout(timeout, client.get_assignments(block_hash)).await {
        Ok(Ok(assignments)) => Ok(assignments),
        Ok(Err(err)) => Err(FetchError::Rpc(err)),
        Err(_) => Err(FetchError::Timeout),
    }
}

/// Reads the safe-harbour flag at the ASM tip.
///
/// Reading at the tip (rather than the buried block) trades finality for latency so the bridge
/// reacts to an emergency about `bury_depth` blocks sooner. The lost finality is recovered by the
/// bridge-side monotonic latch, which never un-latches even if the tip later reorgs.
async fn fetch_safe_harbour(
    client: &HttpClient,
    timeout: time::Duration,
) -> Result<Option<SafeHarbour>, FetchError> {
    let status = match time::timeout(timeout, client.get_status()).await {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => return Err(FetchError::Rpc(err)),
        Err(_) => return Err(FetchError::Timeout),
    };

    let Some(cur_block) = status.cur_block else {
        // ASM has not processed any block yet; there is nothing to read.
        return Ok(None);
    };
    let tip_hash = cur_block.blkid().to_block_hash();

    match time::timeout(timeout, client.get_safe_harbour(tip_hash)).await {
        Ok(Ok(safe_harbour)) => Ok(safe_harbour),
        Ok(Err(err)) => Err(FetchError::Rpc(err)),
        Err(_) => Err(FetchError::Timeout),
    }
}
