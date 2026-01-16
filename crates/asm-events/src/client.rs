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
// TODO: (@prajwolrg): explicitly detect lag vs fork divergence and surface a clear health signal.

use std::{marker::PhantomData, sync::Arc};

use algebra::retry::{retry_with, Strategy};
use bitcoin::BlockHash;
use btc_tracker::event::BlockStatus;
use futures::StreamExt;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_asm_rpc::traits::AssignmentsApiClient;
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::{self, JoinHandle},
    time,
};
use tracing::{debug, error, info, warn};

use crate::{config::AsmRpcConfig, event::AssignmentsState, subscription::Subscription};

/// Marker type indicating the feed is not attached to a block stream yet.
#[derive(Debug)]
pub struct Detached;

/// Marker type indicating the feed is attached to a block stream and subscriptions are available.
#[derive(Debug)]
pub struct Attached;

/// ASM event feed, currently providing assignment state updates.
#[derive(Debug, Clone)]
pub struct AsmEventFeed<State = Detached> {
    cfg: AsmRpcConfig,
    subscribers: Arc<Mutex<Vec<mpsc::UnboundedSender<AssignmentsState>>>>,
    thread_handle: Option<Arc<JoinHandle<()>>>,
    _state: PhantomData<State>,
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
    pub fn new(cfg: AsmRpcConfig) -> AsmEventFeed<Detached> {
        AsmEventFeed {
            cfg,
            subscribers: Arc::new(Mutex::new(Vec::new())),
            thread_handle: None,
            _state: PhantomData,
        }
    }

    /// Attaches the ASM feed to a btc-tracker block subscription and starts workers.
    ///
    /// Call this once before subscribing to ASM-derived event streams. Consumes the feed and
    /// returns the attached version.
    ///
    /// Note: this does not validate ASM RPC connectivity. The feed will retry and surface
    /// failures via logs; if a fail-fast check is desired, add an explicit probe at bootstrap.
    /// The block forwarder stays lightweight so block intake never stalls on ASM RPC latency,
    /// while the fetcher handles timeouts/retries and fanout.
    pub fn attach_block_stream(
        self,
        block_sub: btc_tracker::subscription::Subscription<btc_tracker::event::BlockEvent>,
    ) -> AsmEventFeed<Attached> {
        let (request_sender, request_receiver) = watch::channel(None);
        let subscribers_worker = self.subscribers.clone();
        let cfg = self.cfg.clone();

        let thread_handle = Arc::new(task::spawn(async move {
            let forwarder = run_block_ref_forwarder(block_sub, request_sender);
            let fetcher = run_assignments_state_fetcher(cfg, request_receiver, subscribers_worker);

            tokio::join!(forwarder, fetcher);
        }));

        AsmEventFeed {
            cfg: self.cfg.clone(),
            subscribers: self.subscribers.clone(),
            thread_handle: Some(thread_handle),
            _state: PhantomData,
        }
    }
}

impl AsmEventFeed<Attached> {
    /// Subscribes to assignment state updates.
    ///
    /// Returns a subscription that will receive [`AssignmentsState`] events for buried blocks.
    pub async fn subscribe_assignments_state(&self) -> Subscription<AssignmentsState> {
        let (send, recv) = mpsc::unbounded_channel();

        self.subscribers.lock().await.push(send);

        Subscription::from_receiver(recv)
    }
}

#[derive(Debug)]
enum FetchError {
    Rpc(jsonrpsee::core::ClientError),
    Timeout,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Rpc(err) => write!(f, "RPC error: {}", err),
            FetchError::Timeout => write!(f, "Request timed out"),
        }
    }
}

impl std::error::Error for FetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FetchError::Rpc(err) => Some(err),
            FetchError::Timeout => None,
        }
    }
}

/// Forwards buried block refs to the assignments fetcher without blocking on RPC latency.
async fn run_block_ref_forwarder(
    mut block_sub: btc_tracker::subscription::Subscription<btc_tracker::event::BlockEvent>,
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

/// Fetches assignment state from ASM and fans it out to subscribers.
///
/// Assumes ASM has already ingested the notified block; lag is handled via retries.
/// Fork divergence or persistent lag can surface as "block not found" or repeated failures;
/// those cases are logged and skipped after retries for now.
async fn run_assignments_state_fetcher(
    cfg: AsmRpcConfig,
    mut request_receiver: watch::Receiver<Option<BlockHash>>,
    subscribers: Arc<Mutex<Vec<mpsc::UnboundedSender<AssignmentsState>>>>,
) {
    let client = match HttpClientBuilder::default().build(&cfg.rpc_url) {
        Ok(client) => client,
        Err(err) => {
            error!(%err, "failed to build ASM RPC client");
            return;
        }
    };

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

        let strategy = retry_strategy(&cfg);
        let timeout = cfg.request_timeout;
        let client_handle = client.clone();

        let result = retry_with(strategy, move || {
            let client_handle = client_handle.clone();
            async move {
                fetch_assignments(&client_handle, block_hash, timeout)
                    .await
                    .map_err(|err| {
                        warn!(?err, %block_hash, "failed to fetch ASM assignments");
                        err
                    })
            }
        })
        .await;

        match result {
            Ok(assignments) => {
                last_processed = Some(block_hash);
                info!(
                    %block_hash,
                    num_assignments = assignments.len(),
                    "received ASM assignment state"
                );

                let event = AssignmentsState {
                    block_hash,
                    assignments,
                };

                let mut subs = subscribers.lock().await;
                subs.retain(|sub| sub.send(event.clone()).is_ok());
            }
            Err(err) => {
                error!(
                    ?err,
                    %block_hash,
                    "exhausted ASM assignment retries; skipping assignment state"
                );
            }
        }
    }
}

fn retry_strategy(cfg: &AsmRpcConfig) -> Strategy<FetchError> {
    let strategy = Strategy::exponential_backoff(
        cfg.retry_initial_delay,
        cfg.retry_max_delay,
        cfg.retry_multiplier as f64,
    );

    if let Some(max_retries) = cfg.max_retries {
        strategy.with_max_retries(max_retries)
    } else {
        strategy
    }
}

async fn fetch_assignments(
    client: &HttpClient,
    block_hash: BlockHash,
    timeout: time::Duration,
) -> Result<Vec<AssignmentEntry>, FetchError> {
    let call = client.get_assignments(block_hash);

    match time::timeout(timeout, call).await {
        Ok(Ok(assignments)) => Ok(assignments),
        Ok(Err(err)) => Err(FetchError::Rpc(err)),
        Err(_) => Err(FetchError::Timeout),
    }
}
