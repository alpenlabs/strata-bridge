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

use algebra::retry::retry_with;
use bitcoin::BlockHash;
use btc_tracker::event::{BlockEvent, BlockStatus};
use futures::StreamExt;
use jsonrpsee::http_client::HttpClient;
use strata_asm_bridge_types::SafeHarbour;
use strata_asm_proto_bridge::AssignmentEntry;
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
/// retries) and the safe-harbour flag is read at the ASM tip for a faster emergency response.
///
/// The two fetches run concurrently and neither gates the other: a failure on one side must never
/// suppress the other, or an ASM lag/fork that breaks assignment fetching would also hide an
/// emergency activation. A failed assignment fetch delivers no assignments (the next buried block
/// carries the full snapshot again); a failed safe-harbour fetch delivers `safe_harbour: None`
/// (unknown this cycle), with the monotonic latch and sweep backstop covering the gap.
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

        // Run both fetches concurrently so neither one's retry budget can suppress or delay the
        // other. Safe-harbour detection in particular must survive a broken assignment fetch.
        let (assignments, safe_harbour) = tokio::join!(
            fetch_assignments_with_retry(&cfg, &client, block_hash),
            fetch_safe_harbour_with_retry(&cfg, &client),
        );
        let both_err = assignments.is_err() && safe_harbour.is_err();

        // A failed assignment fetch yields no assignments for this block. Assignments are a
        // snapshot rather than a delta, so the next buried block carries anything missed here.
        let assignments = match assignments {
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
                Vec::new()
            }
        };

        // A failed safe-harbour fetch delivers `None` (unknown this cycle). The monotonic latch and
        // sweep backstop cover the gap.
        let safe_harbour = match safe_harbour {
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

        // Both sides failed, so there is nothing to publish; leave the block unprocessed.
        if both_err {
            continue;
        }

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

async fn fetch_assignments_with_retry(
    cfg: &AsmRpcConfig,
    client: &HttpClient,
    block_hash: BlockHash,
) -> Result<Vec<AssignmentEntry>, FetchError> {
    let timeout = cfg.request_timeout;
    let strategy = cfg.retry_strategy();
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
    let strategy = cfg.retry_strategy();
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

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use bitcoin::hashes::Hash;
    use jsonrpsee::{
        core::RpcResult,
        http_client::HttpClientBuilder,
        server::{ServerBuilder, ServerHandle},
        types::ErrorObjectOwned,
    };
    use strata_asm_bridge_types::SafeHarbourAddress;
    use strata_asm_checkpoint_types::CheckpointTip;
    use strata_asm_common::{AnchorState, AsmManifest};
    use strata_asm_params::AsmParams;
    use strata_asm_proto_bridge::DepositEntry;
    use strata_asm_rpc::traits::{AsmControlApiServer, AsmStateApiServer};
    use strata_asm_worker::AsmWorkerStatus;
    use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Mock ASM RPC whose assignment and safe-harbour paths fail independently, so tests can
    /// break one while the other keeps working.
    #[derive(Clone)]
    struct MockAsm {
        tip: L1BlockCommitment,
        safe_harbour: Option<SafeHarbour>,
        fail_assignments: Arc<AtomicBool>,
        fail_safe_harbour: Arc<AtomicBool>,
    }

    fn mock_err() -> ErrorObjectOwned {
        ErrorObjectOwned::owned(-32000, "mock failure", None::<()>)
    }

    #[async_trait]
    impl AsmControlApiServer for MockAsm {
        async fn get_uptime(&self) -> RpcResult<u64> {
            Ok(0)
        }

        async fn get_status(&self) -> RpcResult<AsmWorkerStatus> {
            Ok(AsmWorkerStatus {
                is_initialized: true,
                cur_block: Some(self.tip),
                cur_state: None,
            })
        }

        async fn get_params(&self) -> RpcResult<AsmParams> {
            Err(mock_err())
        }
    }

    #[async_trait]
    impl AsmStateApiServer for MockAsm {
        async fn get_assignments(&self, _block_hash: BlockHash) -> RpcResult<Vec<AssignmentEntry>> {
            if self.fail_assignments.load(Ordering::Relaxed) {
                return Err(mock_err());
            }
            Ok(Vec::new())
        }

        async fn get_deposits(&self, _block_hash: BlockHash) -> RpcResult<Vec<DepositEntry>> {
            Err(mock_err())
        }

        async fn get_safe_harbour(&self, _block_hash: BlockHash) -> RpcResult<Option<SafeHarbour>> {
            if self.fail_safe_harbour.load(Ordering::Relaxed) {
                return Err(mock_err());
            }
            Ok(self.safe_harbour.clone())
        }

        async fn get_checkpoint_tip(
            &self,
            _block_hash: BlockHash,
        ) -> RpcResult<Option<CheckpointTip>> {
            Err(mock_err())
        }

        async fn get_anchor_state(&self, _block_hash: BlockHash) -> RpcResult<Option<AnchorState>> {
            Err(mock_err())
        }

        async fn get_manifest(&self, _block_hash: BlockHash) -> RpcResult<Option<AsmManifest>> {
            Err(mock_err())
        }
    }

    /// A [`run_asm_state_fetcher`] instance wired to an in-process mock ASM server.
    struct Harness {
        request_tx: watch::Sender<Option<BlockHash>>,
        state_rx: mpsc::UnboundedReceiver<AsmState>,
        health: Arc<StdMutex<Vec<AsmFeedHealthEvent>>>,
        _server: ServerHandle,
    }

    async fn spawn_fetcher(mock: MockAsm) -> Harness {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind mock ASM server");
        let addr = server.local_addr().expect("mock server addr");
        let mut module = AsmControlApiServer::into_rpc(mock.clone());
        module
            .merge(AsmStateApiServer::into_rpc(mock))
            .expect("merge RPC modules");
        let server_handle = server.start(module);

        let rpc_url = format!("http://{addr}");
        let client = HttpClientBuilder::default()
            .build(&rpc_url)
            .expect("mock ASM client");
        let cfg = AsmRpcConfig {
            rpc_url,
            request_timeout: Duration::from_secs(1),
            max_retries: 1,
            retry_initial_delay: Duration::from_millis(5),
            retry_max_delay: Duration::from_millis(10),
            retry_multiplier: 2,
        };

        let (request_tx, request_rx) = watch::channel(None);
        let (state_tx, state_rx) = mpsc::unbounded_channel();
        let health = Arc::new(StdMutex::new(Vec::new()));
        let health_sink = health.clone();
        let observer = HealthObserver(Arc::new(move |event| {
            health_sink.lock().unwrap().push(event);
        }));

        task::spawn(run_asm_state_fetcher(
            cfg,
            client,
            request_rx,
            Arc::new(Mutex::new(vec![state_tx])),
            Some(observer),
        ));

        Harness {
            request_tx,
            state_rx,
            health,
            _server: server_handle,
        }
    }

    impl Harness {
        fn request(&self, block_hash: BlockHash) {
            self.request_tx
                .send(Some(block_hash))
                .expect("fetcher alive");
        }

        async fn recv_state(&mut self) -> AsmState {
            time::timeout(TEST_TIMEOUT, self.state_rx.recv())
                .await
                .expect("AsmState before timeout")
                .expect("subscriber channel open")
        }

        fn saw_health(&self, pred: impl Fn(&AsmFeedHealthEvent) -> bool) -> bool {
            self.health.lock().unwrap().iter().any(pred)
        }

        async fn wait_for_health(&self, pred: impl Fn(&AsmFeedHealthEvent) -> bool) {
            time::timeout(TEST_TIMEOUT, async {
                while !self.saw_health(&pred) {
                    time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("health event before timeout");
        }
    }

    fn activated_safe_harbour() -> SafeHarbour {
        // `[2u8; 32]` is a valid x-only pubkey; see the bitcoin-bosd `new_p2tr` doctest.
        let descriptor = bitcoin_bosd::Descriptor::new_p2tr(&[2u8; 32]).expect("valid x-only key");
        let address = SafeHarbourAddress::try_from(descriptor).expect("p2tr descriptor accepted");
        let mut safe_harbour = SafeHarbour::new(address);
        safe_harbour.set_activated(true);
        safe_harbour
    }

    fn mock_asm(fail_assignments: bool, fail_safe_harbour: bool) -> MockAsm {
        MockAsm {
            tip: L1BlockCommitment::new(100, L1BlockId::from(Buf32([9u8; 32]))),
            safe_harbour: Some(activated_safe_harbour()),
            fail_assignments: Arc::new(AtomicBool::new(fail_assignments)),
            fail_safe_harbour: Arc::new(AtomicBool::new(fail_safe_harbour)),
        }
    }

    fn block_hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    /// An assignment-fetch failure (e.g. ASM lag or fork divergence at the buried block) must not
    /// suppress safe-harbour detection at the tip.
    #[tokio::test]
    async fn safe_harbour_delivery_survives_assignment_fetch_failure() {
        let mut harness = spawn_fetcher(mock_asm(true, false)).await;

        harness.request(block_hash(1));
        let state = harness.recv_state().await;

        assert_eq!(state.block_hash, block_hash(1));
        assert!(state.assignments.is_empty());
        assert!(
            state
                .safe_harbour
                .as_ref()
                .is_some_and(SafeHarbour::is_activated)
        );
        assert!(harness.saw_health(|e| matches!(e, AsmFeedHealthEvent::AssignmentsFetchFailed)));
        assert!(harness.saw_health(|e| matches!(e, AsmFeedHealthEvent::SafeHarbourFetched)));
    }

    /// A safe-harbour fetch failure must not block assignment delivery; the flag is delivered as
    /// unknown (`None`) instead.
    #[tokio::test]
    async fn assignment_delivery_survives_safe_harbour_fetch_failure() {
        let mut harness = spawn_fetcher(mock_asm(false, true)).await;

        harness.request(block_hash(2));
        let state = harness.recv_state().await;

        assert_eq!(state.block_hash, block_hash(2));
        assert!(state.safe_harbour.is_none());
        assert!(harness.saw_health(|e| matches!(e, AsmFeedHealthEvent::AssignmentsFetched)));
        assert!(harness.saw_health(|e| matches!(e, AsmFeedHealthEvent::SafeHarbourFetchFailed)));
    }

    /// When both fetches fail there is nothing to publish; the cycle is skipped and the next
    /// buried block recovers.
    #[tokio::test]
    async fn total_fetch_failure_publishes_nothing_and_recovers() {
        let mock = mock_asm(true, true);
        let fail_assignments = mock.fail_assignments.clone();
        let fail_safe_harbour = mock.fail_safe_harbour.clone();
        let mut harness = spawn_fetcher(mock).await;

        harness.request(block_hash(1));
        harness
            .wait_for_health(|e| matches!(e, AsmFeedHealthEvent::AssignmentsFetchFailed))
            .await;
        harness
            .wait_for_health(|e| matches!(e, AsmFeedHealthEvent::SafeHarbourFetchFailed))
            .await;

        fail_assignments.store(false, Ordering::Relaxed);
        fail_safe_harbour.store(false, Ordering::Relaxed);
        harness.request(block_hash(2));

        // The failed cycle published nothing, so the first delivered state is block 2's.
        let state = harness.recv_state().await;
        assert_eq!(state.block_hash, block_hash(2));
        assert!(
            state
                .safe_harbour
                .as_ref()
                .is_some_and(SafeHarbour::is_activated)
        );
    }
}
