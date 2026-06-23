//! This module contains the top level BtcNotifyClient implementation.
//!
//! Once the client is initialized, consumers of this API will create [`Subscription`]s with
//! [`BtcNotifyClient::subscribe_blocks`] or [`BtcNotifyClient::subscribe_transactions`]. These
//! subscription objects can be primarily worked with via their [`futures::Stream`] trait API.
use std::{
    collections::VecDeque, error::Error, fmt, marker::PhantomData, sync::Arc, time::Duration,
};

use algebra::retry::{retry_with, Strategy};
use bitcoin::{Block, Transaction};
use bitcoincore_zmq::{subscribe_async_wait_handshake, Message, SocketMessage};
use futures::{future::join_all, StreamExt};
use strata_bridge_primitives::subscription::Subscription;
use tokio::{
    sync::{mpsc, Mutex},
    task::{self, JoinHandle},
};
use tracing::{debug, error, info, trace, warn};

use crate::{
    config::BtcNotifyConfig,
    event::{BlockEvent, BlockStatus, TxEvent},
    state_machine::{BtcNotifySM, TxPredicate},
};

// State marker types for the typestate pattern

/// Marker type indicating the client is disconnected from bitcoind.
#[derive(Debug)]
pub struct Disconnected;

/// Marker type indicating the client is connected to bitcoind with an active monitoring thread.
#[derive(Debug)]
pub struct Connected;

struct TxSubscriptionDetails {
    predicate: TxPredicate,
    outbox: mpsc::UnboundedSender<TxEvent>,
}

/// Health events emitted by the Bitcoin ZMQ notification client.
#[derive(Debug, Clone, Copy)]
pub enum BtcNotifyHealthEvent {
    /// The ZMQ stream delivered a message.
    MessageReceived,

    /// The ZMQ stream delivered an error.
    MessageError,

    /// The ZMQ stream ended.
    StreamEnded,
}

#[derive(Clone)]
struct HealthObserver(Arc<dyn Fn(BtcNotifyHealthEvent) + Send + Sync>);

impl HealthObserver {
    fn observe(&self, event: BtcNotifyHealthEvent) {
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

// Coverage is disabled because when tests pass, most Debug impls will never be invoked.
#[coverage(off)]
impl std::fmt::Debug for TxSubscriptionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxSubscriptionDetails")
            .field("predicate", &format!("{:?}", Arc::as_ptr(&self.predicate)))
            .field("outbox", &self.outbox)
            .finish()
    }
}

/// Main structure responsible for processing ZMQ notifications and feeding the appropriate events
/// to its subscribers.
///
/// Uses the typestate pattern to enforce connection state at compile time.
/// - `BtcNotifyClient<Disconnected>`: Client is created but not connected to bitcoind
/// - `BtcNotifyClient<Connected>`: Client is connected and monitoring thread is active
#[derive(Debug, Clone)]
pub struct BtcNotifyClient<State = Disconnected> {
    bury_depth: usize,
    start_height: Option<u64>,
    sockets: Vec<String>,
    block_subs: Arc<Mutex<Vec<mpsc::UnboundedSender<BlockEvent>>>>,
    tx_subs: Arc<Mutex<Vec<TxSubscriptionDetails>>>,
    state_machine: Arc<Mutex<BtcNotifySM>>,
    thread_handle: Option<Arc<JoinHandle<()>>>,
    health_observer: Option<HealthObserver>,

    _state: PhantomData<State>,
}

// Drop implementation for all states
impl<State> Drop for BtcNotifyClient<State> {
    fn drop(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            handle.abort();
        }
    }
}

/// Trait for fetching blocks by height.
#[async_trait::async_trait]
pub trait BlockFetcher {
    /// Error type for block fetching failures.
    type Error;

    /// Fetches a block by its height.
    ///
    /// Implementations should handle their own retry strategies and only return
    /// an error if all retries have been exhausted.
    async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error>;
}

/// Handles a `rawblock` ZMQ message and returns transaction events produced by it.
///
/// The handler enforces the configured start height, backfills any height gap before the received
/// block, and then processes the resulting contiguous block list in order. `cursor` is advanced by
/// the lower-level block processor for each block that is accepted.
async fn process_block_message<F>(
    block: Block,
    cursor: &mut u64,
    start_height: u64,
    sm: &mut BtcNotifySM,
    fetcher: &Arc<F>,
    block_subs: &Arc<Mutex<Vec<mpsc::UnboundedSender<BlockEvent>>>>,
) -> Vec<TxEvent>
where
    F: BlockFetcher + Send + Sync + 'static,
    <F as BlockFetcher>::Error: std::fmt::Debug + Send,
{
    let received_height = match block.bip34_block_height() {
        Ok(block_height) => block_height,
        Err(e) => {
            error!(?e, block_hash = %block.block_hash(),
                "could not determine block height, skipping block");
            return Vec::new();
        }
    };

    if start_height > received_height {
        warn!(%received_height, %start_height, "start height is in the future, skipping block");
        return Vec::new();
    }

    if let Some(next_expected_height) = sm.next_expected_block_height() {
        let realigned_cursor = next_expected_height.max(start_height);
        if realigned_cursor != *cursor {
            warn!(
                cursor = %*cursor,
                %next_expected_height,
                %start_height,
                %realigned_cursor,
                "block cursor diverged from state machine tip, realigning cursor"
            );
            *cursor = realigned_cursor;
        }
    }

    if received_height < *cursor {
        warn!(%received_height, cursor = %*cursor, "received block is behind cursor, skipping block");
        return Vec::new();
    }

    debug!("received block at height {received_height}, expected {cursor}");

    // Backfill any skipped blocks in the range:
    // [cursor, received_height).
    // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2680>
    // Process massive backlogs in bounded batches instead of all
    // at once to avoid excessive memory use after prolonged
    // downtime.
    let mut blocks = match join_all((*cursor..received_height).map(|height| {
        debug!(%height, "fetching lagged block");
        let fetcher = fetcher.clone();
        async move { fetcher.fetch_block(height).await }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()
    {
        Ok(skipped_blocks) => skipped_blocks,
        Err(e) => {
            error!(?e, "failed to backfill lagged blocks");
            // if we can't fetch any of the skipped blocks,
            // then we wait for the next ZMQ event and try
            // again since returning intermediate/broken stream
            // of blocks may introduce unpredictable weirdness.
            return Vec::new();
        }
    };

    blocks.push(block); // add the one from ZMQ

    let mut all_tx_events = Vec::new();
    for block in blocks {
        all_tx_events.extend(process_connected_block(block, cursor, sm, block_subs).await);
    }

    all_tx_events
}

/// Applies one block to subscribers and the state machine.
///
/// The block is announced as mined, processed for transaction state transitions, and any resulting
/// block event is forwarded to block subscribers. On success the cursor is moved past the processed
/// block and the transaction diff is returned to the caller.
async fn process_connected_block(
    block: Block,
    cursor: &mut u64,
    sm: &mut BtcNotifySM,
    block_subs: &Arc<Mutex<Vec<mpsc::UnboundedSender<BlockEvent>>>>,
) -> Vec<TxEvent> {
    let height = block.bip34_block_height().unwrap_or(0);
    let block_hash = block.block_hash();

    if !sm.can_connect_block(&block) {
        warn!(
            %height,
            %block_hash,
            cursor = %*cursor,
            "block does not connect to state machine tip, leaving cursor unchanged"
        );
        return Vec::new();
    }

    // First send the block to the block subscribers.
    // if the receiver has been dropped, we remove it from the
    // subscription list.
    block_subs.lock().await.retain(|sub| {
        sub.send(BlockEvent {
            block: block.clone(),
            status: BlockStatus::Mined,
        })
        .is_ok()
    });

    // Now we process the block to understand what the relevant
    // transaction diff is.
    trace!(?block, "processing block");
    let height_string = block
        .bip34_block_height()
        .map_or_else(|_| "UNKNOWN".to_string(), |h| h.to_string());
    info!(block_height=%height_string, block_hash=%block.block_hash(), "processing block");
    let (tx_events, block_event) = sm.process_block(block);

    if let Some(block_event) = block_event {
        block_subs
            .lock()
            .await
            .retain(|sub| sub.send(block_event.clone()).is_ok())
    }

    *cursor = height.saturating_add(1);

    tx_events
}

// Implementation for Disconnected state
impl BtcNotifyClient<Disconnected> {
    /// Creates a new disconnected client.
    ///
    /// The client is initialized but not connected to bitcoind. Use `connect()` to establish
    /// the ZMQ subscription and transition to the Connected state.
    pub fn new(cfg: &BtcNotifyConfig, unburied_blocks: VecDeque<Block>) -> Self {
        let sockets = cfg
            .hashblock_connection_string
            .iter()
            .chain(cfg.hashtx_connection_string.iter())
            .chain(cfg.rawblock_connection_string.iter())
            .chain(cfg.rawtx_connection_string.iter())
            .chain(cfg.sequence_connection_string.iter())
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        let state_machine = Arc::new(Mutex::new(BtcNotifySM::init(
            cfg.bury_depth,
            unburied_blocks,
        )));
        let block_subs = Arc::new(Mutex::new(Vec::new()));
        let tx_subs = Arc::new(Mutex::new(Vec::new()));

        Self {
            bury_depth: cfg.bury_depth,
            sockets,
            block_subs,
            tx_subs,
            state_machine,
            thread_handle: None,
            start_height: None,
            health_observer: None,
            _state: PhantomData,
        }
    }

    /// Connects to bitcoind and starts the ZMQ subscription thread.
    ///
    /// Consumes the disconnected client and returns a connected client.
    /// The connected client will have an active monitoring thread that processes ZMQ events.
    ///
    /// The ZMQ subscription handshake is retried with a short per-attempt timeout and a fixed
    /// delay between attempts. This tolerates a brief window after a bitcoind restart during
    /// which the RPC server is reachable but the ZMQ publishers have not yet bound their
    /// endpoints.
    pub async fn connect<F>(
        self,
        start_height: u64,
        fetcher: F,
    ) -> Result<BtcNotifyClient<Connected>, Box<dyn Error>>
    where
        F: BlockFetcher + Send + Sync + 'static,
        <F as BlockFetcher>::Error: std::fmt::Debug + Send,
    {
        /// Per-attempt timeout for the ZMQ subscription handshake.
        const HANDSHAKE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
        /// Delay between successive ZMQ handshake attempts.
        const HANDSHAKE_RETRY_BACKOFF: Duration = Duration::from_millis(500);
        /// Maximum number of retry attempts beyond the initial attempt. Total elapsed time is
        /// bounded by roughly
        /// `(HANDSHAKE_ATTEMPT_TIMEOUT + HANDSHAKE_RETRY_BACKOFF) * (1 + HANDSHAKE_MAX_RETRIES)`.
        const HANDSHAKE_MAX_RETRIES: usize = 11;

        trace!(sockets=?self.sockets, "subscribing to bitcoind");

        let sockets = self.sockets.clone();
        let strategy =
            Strategy::fixed_delay(HANDSHAKE_RETRY_BACKOFF).with_max_retries(HANDSHAKE_MAX_RETRIES);
        let mut stream = retry_with(strategy, move || {
            let sockets = sockets.clone();
            async move {
                let urls: Vec<&str> = sockets.iter().map(String::as_str).collect();
                match tokio::time::timeout(
                    HANDSHAKE_ATTEMPT_TIMEOUT,
                    subscribe_async_wait_handshake(&urls),
                )
                .await
                {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(err)) => {
                        warn!(?err, "zmq subscription handshake attempt failed, retrying");
                        Err(format!("subscribe error: {err}"))
                    }
                    Err(_) => {
                        warn!(
                            attempt_timeout = ?HANDSHAKE_ATTEMPT_TIMEOUT,
                            "zmq subscription handshake attempt timed out, retrying"
                        );
                        Err(format!("timed out after {HANDSHAKE_ATTEMPT_TIMEOUT:?}"))
                    }
                }
            }
        })
        .await
        .map_err(|last_err: String| -> Box<dyn Error> {
            format!(
                "bitcoin-core zmq subscription handshake failed after {} attempts: last error: {last_err}",
                HANDSHAKE_MAX_RETRIES + 1
            )
            .into()
        })?;

        // Clone references for the spawned thread
        let block_subs_thread = self.block_subs.clone();
        let tx_subs_thread = self.tx_subs.clone();
        let state_machine_thread = self.state_machine.clone();
        let fetcher = Arc::new(fetcher);
        let health_observer = self.health_observer.clone();

        let mut cursor = start_height;
        let thread_handle = Arc::new(task::spawn(async move {
            // Drains ZMQ events until the stream ends (only when the BtcNotifyClient is dropped),
            // then emits `StreamEnded` and lets the task exit.
            info!("listening for ZMQ events");

            while let Some(res) = stream.next().await {
                let mut sm = state_machine_thread.lock().await;
                let diff = match res {
                    Ok(SocketMessage::Message(msg)) => {
                        if let Some(observer) = &health_observer {
                            observer.observe(BtcNotifyHealthEvent::MessageReceived);
                        }
                        let topic = msg.topic_str();
                        match msg {
                            Message::HashBlock(_, _) => {
                                trace!(%topic, "received event");
                                Vec::new()
                            }
                            Message::HashTx(_, _) => {
                                trace!(%topic, "received event");
                                Vec::new()
                            }
                            Message::Block(block, _) => {
                                trace!(%topic, "received event");

                                process_block_message(
                                    block,
                                    &mut cursor,
                                    start_height,
                                    &mut sm,
                                    &fetcher,
                                    &block_subs_thread,
                                )
                                .await
                            }
                            Message::Tx(tx, _) => {
                                trace!(%topic, "received event");
                                info!(txid=%tx.compute_txid(), "processing transaction");
                                sm.process_tx(tx)
                            }
                            Message::Sequence(seq, _) => {
                                trace!(%topic, "received event");
                                info!(%seq, "processing sequence");
                                let (tx_events, block_event) = sm.process_sequence(seq);

                                if let Some(block_event) = block_event {
                                    if matches!(&block_event.status, BlockStatus::Uncled) {
                                        let disconnected_height = block_event
                                            .block
                                            .bip34_block_height()
                                            .unwrap_or(start_height);
                                        let realigned_cursor =
                                            disconnected_height.max(start_height);
                                        if realigned_cursor < cursor {
                                            warn!(
                                                cursor = %cursor,
                                                %disconnected_height,
                                                %start_height,
                                                %realigned_cursor,
                                                "block disconnect rolled back state machine tip, realigning cursor"
                                            );
                                            cursor = realigned_cursor;
                                        }
                                    }

                                    block_subs_thread
                                        .lock()
                                        .await
                                        .retain(|sub| sub.send(block_event.clone()).is_ok())
                                }

                                tx_events
                            }
                        }
                    }
                    Ok(monitoring_msg) => {
                        if let Some(observer) = &health_observer {
                            observer.observe(BtcNotifyHealthEvent::MessageReceived);
                        }
                        warn!(?monitoring_msg, "ignoring monitoring message");
                        Vec::new()
                    }
                    Err(e) => {
                        if let Some(observer) = &health_observer {
                            observer.observe(BtcNotifyHealthEvent::MessageError);
                        }
                        error!(%e, "Error processing ZMQ message");
                        Vec::new()
                    }
                };

                tx_subs_thread.lock().await.retain(|sub| {
                    for msg in diff.iter().filter(|event| (sub.predicate)(&event.rawtx)) {
                        // Now we send the diff to the relevant subscribers.
                        // If we ever encounter a send error,
                        // it means the receiver has been dropped.
                        trace!(?msg, "notifying subscriber");

                        if let Err(e) = sub.outbox.send(msg.clone()) {
                            debug!(%e, "failed to notify subscriber");
                            sm.rm_filter(&sub.predicate);
                            return false;
                        }
                    }
                    true
                });
            }

            if let Some(observer) = &health_observer {
                observer.observe(BtcNotifyHealthEvent::StreamEnded);
            }
        }));

        info!("subscribed to bitcoind");

        Ok(BtcNotifyClient {
            bury_depth: self.bury_depth,
            sockets: self.sockets.clone(),
            block_subs: self.block_subs.clone(),
            tx_subs: self.tx_subs.clone(),
            state_machine: self.state_machine.clone(),
            thread_handle: Some(thread_handle),
            start_height: Some(start_height),
            health_observer: self.health_observer.clone(),
            _state: PhantomData,
        })
    }
}

impl<State> BtcNotifyClient<State> {
    /// Installs a synchronous health observer for Bitcoin ZMQ stream health.
    pub fn with_health_observer(
        mut self,
        observer: impl Fn(BtcNotifyHealthEvent) + Send + Sync + 'static,
    ) -> Self {
        self.health_observer = Some(HealthObserver(Arc::new(observer)));
        self
    }
}

// Implementation for Connected state
impl BtcNotifyClient<Connected> {
    /// Gracefully disconnects from bitcoind and transitions back to Disconnected state.
    ///
    /// Consumes the connected client and returns a disconnected client.
    /// The monitoring thread is aborted when this method is called.
    pub fn disconnect(mut self) -> BtcNotifyClient<Disconnected> {
        if let Some(thread_handle) = self.thread_handle.take() {
            thread_handle.abort();
        }

        BtcNotifyClient {
            bury_depth: self.bury_depth,
            sockets: self.sockets.clone(),
            block_subs: self.block_subs.clone(),
            tx_subs: self.tx_subs.clone(),
            state_machine: self.state_machine.clone(),
            thread_handle: None,
            start_height: None,
            health_observer: self.health_observer.clone(),
            _state: PhantomData,
        }
    }

    /// Creates a new [`Subscription`] that emits new [`bitcoin::Transaction`] and
    /// [`TxStatus`](crate::event::TxStatus)
    /// every time a transaction's status changes due to block or mempool events.
    ///
    /// Only available when the client is in the Connected state.
    pub async fn subscribe_transactions(
        &self,
        f: impl Fn(&Transaction) -> bool + Sync + Send + 'static,
    ) -> Subscription<TxEvent> {
        let (send, recv) = mpsc::unbounded_channel();
        let predicate = Arc::new(f);

        {
            trace!("locking state machine");
            let mut sm = self.state_machine.lock().await;
            sm.add_filter(predicate.clone());
            trace!("added filter to state machine");
        }

        let details = TxSubscriptionDetails {
            predicate,
            outbox: send,
        };

        trace!(?details, "subscribing to transactions");

        {
            trace!("locking subscriptions");
            let mut subs = self.tx_subs.lock().await;
            subs.push(details);
            trace!("added subscription");
        }

        Subscription::from_receiver(recv)
    }

    /// Creates a new [`Subscription`] that emits new [`bitcoin::Block`] every time a new block is
    /// connected to the main Bitcoin blockchain.
    ///
    /// Only available when the client is in the Connected state.
    pub async fn subscribe_blocks(&self) -> Subscription<BlockEvent> {
        let (send, recv) = mpsc::unbounded_channel();

        trace!("subscribing to blocks");

        self.block_subs.lock().await.push(send);

        Subscription::from_receiver(recv)
    }

    /// Returns the number of active transaction subscriptions created with
    /// [`BtcNotifyClient::subscribe_transactions`].
    pub async fn num_tx_subscriptions(&self) -> usize {
        self.tx_subs.lock().await.len()
    }

    /// Returns the number of active block subscriptions created with
    /// [`BtcNotifyClient::subscribe_blocks`].
    pub async fn num_block_subscriptions(&self) -> usize {
        self.block_subs.lock().await.len()
    }

    /// Returns the start height configured when connecting.
    pub const fn start_height(&self) -> u64 {
        self.start_height
            .expect("must have start height in connected state")
    }
}

// Shared methods available in both states
impl<State> BtcNotifyClient<State> {
    /// Returns the configured bury depth.
    pub const fn bury_depth(&self) -> usize {
        self.bury_depth
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::{Arc, Mutex as StdMutex},
    };

    use bitcoin::{
        absolute::LockTime, block, hashes::Hash, script::Builder, transaction, Amount, BlockHash,
        CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use bitcoincore_zmq::SequenceMessage;

    use super::*;
    use crate::{constants::DEFAULT_BURY_DEPTH, event::BlockStatus};

    #[derive(Clone)]
    struct StaticFetcher {
        blocks: Arc<BTreeMap<u64, Block>>,
        fetched_heights: Arc<StdMutex<Vec<u64>>>,
    }

    #[async_trait::async_trait]
    impl BlockFetcher for StaticFetcher {
        type Error = String;

        async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
            self.fetched_heights.lock().unwrap().push(height);
            self.blocks
                .get(&height)
                .cloned()
                .ok_or_else(|| format!("missing block at height {height}"))
        }
    }

    fn test_block(height: u64, prev_blockhash: BlockHash, nonce: u32) -> Block {
        let coinbase = Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(height as i64).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let header = block::Header {
            version: block::Version::TWO,
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: height as u32,
            bits: CompactTarget::from_consensus(u32::MAX),
            nonce,
        };
        let mut block = Block {
            header,
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        block
    }

    #[tokio::test]
    async fn backfills_missing_block_after_reorg_disconnect_rolls_back_state_tip() {
        const BASE_HEIGHT: u64 = 18;
        let base = test_block(BASE_HEIGHT, BlockHash::all_zeros(), 1);
        let stale_child = test_block(BASE_HEIGHT + 1, base.block_hash(), 2);
        let canonical_child = test_block(BASE_HEIGHT + 1, base.block_hash(), 3);
        let canonical_grandchild = test_block(BASE_HEIGHT + 2, canonical_child.block_hash(), 4);

        let mut fetchable_blocks = BTreeMap::new();
        fetchable_blocks.insert(BASE_HEIGHT + 1, canonical_child.clone());
        let fetched_heights = Arc::new(StdMutex::new(Vec::new()));
        let fetcher = Arc::new(StaticFetcher {
            blocks: Arc::new(fetchable_blocks),
            fetched_heights: fetched_heights.clone(),
        });

        let mut sm = BtcNotifySM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
        let block_subs = Arc::new(Mutex::new(Vec::new()));
        let mut cursor = BASE_HEIGHT;

        process_block_message(
            base,
            &mut cursor,
            BASE_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;
        assert_eq!(cursor, BASE_HEIGHT + 1);

        process_block_message(
            stale_child.clone(),
            &mut cursor,
            BASE_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;
        assert_eq!(cursor, BASE_HEIGHT + 2);

        let (_tx_events, disconnected) = sm.process_sequence(SequenceMessage::BlockDisconnect {
            blockhash: stale_child.block_hash(),
        });
        let disconnected = disconnected.expect("disconnect should emit block event");
        assert_eq!(disconnected.status, BlockStatus::Uncled);
        let disconnected_height = disconnected
            .block
            .bip34_block_height()
            .unwrap_or(BASE_HEIGHT);
        let realigned_cursor = disconnected_height.max(BASE_HEIGHT);
        if realigned_cursor < cursor {
            cursor = realigned_cursor;
        }
        assert_eq!(cursor, BASE_HEIGHT + 1);

        sm.process_sequence(SequenceMessage::BlockConnect {
            blockhash: canonical_child.block_hash(),
        });
        sm.process_sequence(SequenceMessage::BlockConnect {
            blockhash: canonical_grandchild.block_hash(),
        });

        process_block_message(
            canonical_grandchild,
            &mut cursor,
            BASE_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;

        assert_eq!(
            *fetched_heights.lock().unwrap(),
            vec![BASE_HEIGHT + 1],
            "canonical child must be backfilled after the disconnect rolled back the state tip"
        );
        assert_eq!(cursor, BASE_HEIGHT + 3);
    }

    #[tokio::test]
    async fn disconnecting_only_tracked_block_rewinds_cursor_for_replacement_block() {
        const BASE_HEIGHT: u64 = 18;
        let stale_base = test_block(BASE_HEIGHT, BlockHash::all_zeros(), 1);
        let canonical_base = test_block(BASE_HEIGHT, BlockHash::all_zeros(), 2);

        let fetched_heights = Arc::new(StdMutex::new(Vec::new()));
        let fetcher = Arc::new(StaticFetcher {
            blocks: Arc::new(BTreeMap::new()),
            fetched_heights,
        });

        let mut sm = BtcNotifySM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
        let block_subs = Arc::new(Mutex::new(Vec::new()));
        let mut cursor = BASE_HEIGHT;

        process_block_message(
            stale_base.clone(),
            &mut cursor,
            BASE_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;
        assert_eq!(cursor, BASE_HEIGHT + 1);

        let (_tx_events, disconnected) = sm.process_sequence(SequenceMessage::BlockDisconnect {
            blockhash: stale_base.block_hash(),
        });
        let disconnected = disconnected.expect("disconnect should emit block event");
        assert_eq!(disconnected.status, BlockStatus::Uncled);
        let disconnected_height = disconnected
            .block
            .bip34_block_height()
            .unwrap_or(BASE_HEIGHT);
        let realigned_cursor = disconnected_height.max(BASE_HEIGHT);
        if realigned_cursor < cursor {
            cursor = realigned_cursor;
        }
        assert_eq!(cursor, BASE_HEIGHT);

        process_block_message(
            canonical_base,
            &mut cursor,
            BASE_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;

        assert_eq!(cursor, BASE_HEIGHT + 1);
        assert_eq!(sm.next_expected_block_height(), Some(BASE_HEIGHT + 1));
    }

    #[tokio::test]
    async fn disconnecting_only_tracked_block_backfills_replacement_before_child() {
        const BASE_HEIGHT: u64 = 18;
        let stale_base = test_block(BASE_HEIGHT, BlockHash::all_zeros(), 1);
        let canonical_base = test_block(BASE_HEIGHT, BlockHash::all_zeros(), 2);
        let canonical_child = test_block(BASE_HEIGHT + 1, canonical_base.block_hash(), 3);

        let mut fetchable_blocks = BTreeMap::new();
        fetchable_blocks.insert(BASE_HEIGHT, canonical_base);
        let fetched_heights = Arc::new(StdMutex::new(Vec::new()));
        let fetcher = Arc::new(StaticFetcher {
            blocks: Arc::new(fetchable_blocks),
            fetched_heights: fetched_heights.clone(),
        });

        let mut sm = BtcNotifySM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
        let block_subs = Arc::new(Mutex::new(Vec::new()));
        let mut cursor = BASE_HEIGHT;

        process_block_message(
            stale_base.clone(),
            &mut cursor,
            BASE_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;
        assert_eq!(cursor, BASE_HEIGHT + 1);

        let (_tx_events, disconnected) = sm.process_sequence(SequenceMessage::BlockDisconnect {
            blockhash: stale_base.block_hash(),
        });
        let disconnected = disconnected.expect("disconnect should emit block event");
        assert_eq!(disconnected.status, BlockStatus::Uncled);
        let disconnected_height = disconnected
            .block
            .bip34_block_height()
            .unwrap_or(BASE_HEIGHT);
        let realigned_cursor = disconnected_height.max(BASE_HEIGHT);
        if realigned_cursor < cursor {
            cursor = realigned_cursor;
        }
        assert_eq!(cursor, BASE_HEIGHT);

        process_block_message(
            canonical_child,
            &mut cursor,
            BASE_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;

        assert_eq!(
            *fetched_heights.lock().unwrap(),
            vec![BASE_HEIGHT],
            "replacement parent must be backfilled before the child is processed"
        );
        assert_eq!(cursor, BASE_HEIGHT + 2);
        assert_eq!(sm.next_expected_block_height(), Some(BASE_HEIGHT + 2));
    }

    #[tokio::test]
    async fn state_tip_realignment_does_not_backfill_before_start_height() {
        const START_HEIGHT: u64 = 20;
        let old_tip = test_block(START_HEIGHT - 2, BlockHash::all_zeros(), 1);
        let first_allowed = test_block(START_HEIGHT, old_tip.block_hash(), 2);

        let fetched_heights = Arc::new(StdMutex::new(Vec::new()));
        let fetcher = Arc::new(StaticFetcher {
            blocks: Arc::new(BTreeMap::new()),
            fetched_heights: fetched_heights.clone(),
        });

        let mut sm = BtcNotifySM::init(DEFAULT_BURY_DEPTH, VecDeque::from([old_tip]));
        let block_subs = Arc::new(Mutex::new(Vec::new()));
        let mut cursor = START_HEIGHT;

        process_block_message(
            first_allowed,
            &mut cursor,
            START_HEIGHT,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;

        assert!(
            fetched_heights.lock().unwrap().is_empty(),
            "realignment must not backfill blocks before the configured start height"
        );
        assert_eq!(cursor, START_HEIGHT + 1);
        assert_eq!(sm.next_expected_block_height(), Some(START_HEIGHT + 1));
    }
}

#[cfg(test)]
mod e2e_tests {
    use std::{path::PathBuf, sync::Mutex as StdMutex, task::Poll};

    use bitcoincore_zmq::SequenceMessage;
    use corepc_node::{client::client_sync::Auth, serde_json::json};
    use proptest::prelude::*;
    use serial_test::serial;
    use strata_bridge_common::logging;
    use strata_bridge_test_utils::prelude::{wait_for_blocks, wait_for_height};
    use tokio::time::timeout;

    use super::*;
    use crate::{constants::DEFAULT_BURY_DEPTH, event::TxStatus};

    async fn setup_node() -> Result<(BtcNotifyConfig, corepc_node::Node), Box<dyn std::error::Error>>
    {
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
        ];
        bitcoin_conf.args.extend(args.iter().map(String::as_str));

        let bitcoind = corepc_node::Node::with_conf("bitcoind", &bitcoin_conf)?;
        let address = bitcoind.client.new_address()?;
        // NOTE: (proofofkeags) for some reason it appears that ZMQ flushes every 5 blocks, or
        // perhaps after a certain number of bytes. This means that even though we should be able to
        // handle everything after [`crate::BIP34_MIN_HEIGHT`], we can't just simply waight for that
        // height since old blocks are still buffered in the zmq socket. It appears to update its
        // internal cursor at block heights 1, 6, 11, 16, and 21. 21 Is the first one that actually
        // works due to BIP34 requirements.
        bitcoind.client.generate_to_address(21, &address)?;
        wait_for_height(&bitcoind, 21).await?;

        let cfg = BtcNotifyConfig::default()
            .with_bury_depth(DEFAULT_BURY_DEPTH)
            .with_hashblock_connection_string(hash_block_socket)
            .with_hashtx_connection_string(hash_tx_socket)
            .with_rawblock_connection_string(raw_block_socket)
            .with_rawtx_connection_string(raw_tx_socket)
            .with_sequence_connection_string(sequence_socket);

        Ok((cfg, bitcoind))
    }

    fn setup_fetcher(rpc_url: &str, cookie_file: PathBuf) -> impl BlockFetcher<Error = String> {
        struct Fetcher(corepc_node::Client);

        #[async_trait::async_trait]
        impl BlockFetcher for Fetcher {
            type Error = String;

            async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
                info!(%height, "fetching block hash");
                let hash = self
                    .0
                    .get_block_hash(height)
                    .inspect_err(|e| {
                        error!(%height, ?e, "failed to fetch block hash");
                    })
                    .map_err(|e| e.to_string())?
                    .block_hash()
                    .expect("must be valid hash");

                info!(%height, %hash, "fetching block for hash");
                let block = self
                    .0
                    .get_block(hash)
                    .inspect_err(|e| {
                        error!(%height, %hash, ?e, "failed to fetch block");
                    })
                    .map_err(|e| e.to_string())?;

                Ok(block)
            }
        }

        let auth = Auth::CookieFile(cookie_file);
        let client = corepc_node::Client::new_with_auth(rpc_url, auth)
            .expect("must be able to create client");

        Fetcher(client)
    }

    async fn setup_client(
    ) -> Result<(BtcNotifyClient<Connected>, corepc_node::Node), Box<dyn std::error::Error>> {
        let (cfg, bitcoind) = setup_node().await?;
        let cookie_file = bitcoind.params.cookie_file.clone();
        let start_height = bitcoind.client.get_block_count()?.0;
        let fetcher = setup_fetcher(&bitcoind.rpc_url(), cookie_file);

        let client = BtcNotifyClient::new(&cfg, VecDeque::new())
            .connect(start_height, fetcher)
            .await?;

        Ok((client, bitcoind))
    }

    async fn setup_two_clients() -> Result<
        (
            BtcNotifyClient<Connected>,
            BtcNotifyClient<Connected>,
            corepc_node::Node,
        ),
        Box<dyn std::error::Error>,
    > {
        let (cfg, bitcoind) = setup_node().await?;
        let cookie_file = bitcoind.params.cookie_file.clone();
        // we want to see if a newly generated block in the test is seen by both clients,
        // for this, we want the first block emitted by the client to be the one generated by the
        // test itself and not the one generated in `setup_node`.
        let start_height = bitcoind.client.get_block_count()?.0.saturating_add(1);

        info!("connecting to bitcoind with client 1");
        let fetcher_1 = setup_fetcher(&bitcoind.rpc_url(), cookie_file.clone());
        let client_1 = BtcNotifyClient::new(&cfg, VecDeque::new())
            .connect(start_height, fetcher_1)
            .await?;

        info!("connecting to bitcoind with client 2");
        let fetcher_2 = setup_fetcher(&bitcoind.rpc_url(), cookie_file);
        let client_2 = BtcNotifyClient::new(&cfg, VecDeque::new())
            .connect(start_height, fetcher_2)
            .await?;

        Ok((client_1, client_2, bitcoind))
    }

    #[tokio::test]
    #[serial]
    async fn chain_reorg_backfills_replacement_parent_before_later_child(
    ) -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        struct RecordingFetcher {
            client: corepc_node::Client,
            fetched_heights: Arc<StdMutex<Vec<u64>>>,
        }

        #[async_trait::async_trait]
        impl BlockFetcher for RecordingFetcher {
            type Error = String;

            async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
                self.fetched_heights.lock().unwrap().push(height);

                let hash = self
                    .client
                    .get_block_hash(height)
                    .map_err(|e| e.to_string())?
                    .block_hash()
                    .expect("must be valid hash");

                self.client.get_block(hash).map_err(|e| e.to_string())
            }
        }

        let (cfg, bitcoind) = setup_node().await?;
        let base_height = bitcoind.client.get_block_count()?.0;
        let base_hash = bitcoind
            .client
            .get_block_hash(base_height)?
            .block_hash()
            .expect("must be valid hash");
        let base = bitcoind.client.get_block(base_hash)?;

        let fetched_heights = Arc::new(StdMutex::new(Vec::new()));
        let fetcher = Arc::new(RecordingFetcher {
            client: corepc_node::Client::new_with_auth(
                &bitcoind.rpc_url(),
                Auth::CookieFile(bitcoind.params.cookie_file.clone()),
            )?,
            fetched_heights: fetched_heights.clone(),
        });
        let block_subs = Arc::new(Mutex::new(Vec::new()));
        let mut sm = BtcNotifySM::init(cfg.bury_depth, VecDeque::new());
        let mut cursor = base_height;

        process_block_message(
            base,
            &mut cursor,
            base_height,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;
        assert_eq!(cursor, base_height + 1);

        let stale_hash = bitcoind
            .client
            .generate_to_address(1, &bitcoind.client.new_address()?)?
            .into_model()?
            .0
            .remove(0);
        let stale = bitcoind.client.get_block(stale_hash)?;

        process_block_message(
            stale,
            &mut cursor,
            base_height,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;
        assert_eq!(cursor, base_height + 2);

        let backfilled_block_height = base_height + 1;
        bitcoind
            .client
            .call::<()>("invalidateblock", &[json!(stale_hash.to_string())])?;
        assert_eq!(
            bitcoind.client.get_block_count()?.0,
            base_height,
            "chain must be back to base height"
        );

        let (_tx_events, disconnected) = sm.process_sequence(SequenceMessage::BlockDisconnect {
            blockhash: stale_hash,
        });
        let disconnected = disconnected.expect("disconnect should emit block event");
        assert_eq!(disconnected.status, BlockStatus::Uncled);
        let disconnected_height = disconnected
            .block
            .bip34_block_height()
            .unwrap_or(base_height);
        let realigned_cursor = disconnected_height.max(base_height);
        if realigned_cursor < cursor {
            cursor = realigned_cursor;
        }
        assert_eq!(cursor, base_height + 1, "cursor must rewind on disconnect");

        let mut canonical_hashes = bitcoind
            .client
            .generate_to_address(2, &bitcoind.client.new_address()?)?
            .into_model()?
            .0;
        let canonical_child_hash = canonical_hashes.remove(0);
        let canonical_grandchild_hash = canonical_hashes.remove(0);
        let canonical_grandchild = bitcoind.client.get_block(canonical_grandchild_hash)?;

        sm.process_sequence(SequenceMessage::BlockConnect {
            blockhash: canonical_child_hash,
        });
        sm.process_sequence(SequenceMessage::BlockConnect {
            blockhash: canonical_grandchild_hash,
        });

        process_block_message(
            canonical_grandchild,
            &mut cursor,
            base_height,
            &mut sm,
            &fetcher,
            &block_subs,
        )
        .await;

        assert_eq!(
            *fetched_heights.lock().unwrap(),
            vec![backfilled_block_height],
            "the replacement parent must be backfilled before the later child is processed"
        );
        assert_eq!(cursor, base_height + 3);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn basic_subscribe_blocks_functionality() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Subscribe to new blocks
        let mut block_sub = client.subscribe_blocks().await;

        // Mine a new block
        let newly_mined = bitcoind
            .client
            .generate_to_address(1, &bitcoind.client.new_address()?)?
            .into_model()?;
        let target_hash = newly_mined.0.first();

        // Wait for a new block to be delivered over the subscription
        timeout(std::time::Duration::from_secs(10), async move {
            while target_hash
                != block_sub
                    .next()
                    .await
                    .map(|b| b.block.block_hash())
                    .as_ref()
            {}
        })
        .await?;

        // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping
        // it earlier, aborting the producer thread
        drop(client);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn multiple_subscribers_receive_same_events() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        info!("setting up two clients");
        let (client_1, client_2, bitcoind) = setup_two_clients().await?;
        info!("subscribing to blocks");

        let mut block_sub_1 = client_1.subscribe_blocks().await;
        let mut block_sub_2 = client_2.subscribe_blocks().await;

        info!("mining block");
        let newly_mined = bitcoind
            .client
            .generate_to_address(1, &bitcoind.client.new_address()?)?
            .into_model()?;

        info!("waiting for block in client 1");
        let blk_1 = block_sub_1.next().await.map(|b| {
            trace!(height=?b.block.bip34_block_height(), "block_sub_1");
            b.block.block_hash()
        });
        info!("got block in client 1");
        info!("waiting for block in client 2");
        let blk_2 = block_sub_2.next().await.map(|b| {
            trace!(height=?b.block.bip34_block_height(), "block_sub_2");
            b.block.block_hash()
        });
        info!("got block in client 2");

        assert_eq!(
            blk_1.as_ref(),
            blk_2.as_ref(),
            "both clients must see the same block"
        );
        assert_eq!(
            blk_1.as_ref(),
            newly_mined.0.first(),
            "the block seen by both clients must be the one that was newly mined"
        );

        // Explicitly drop the clients here to prevent rustc from "optimizing" the code and dropping
        // them earlier, aborting the producer thread
        drop(client_1);
        drop(client_2);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn basic_subscribe_transactions_functionality() -> Result<(), Box<dyn std::error::Error>>
    {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Subscribe to all transactions.
        let mut tx_sub = client.subscribe_transactions(|_| true).await;

        // Mine a new block.
        let newly_mined = bitcoind
            .client
            .generate_to_address(1, &bitcoind.client.new_address()?)?
            .into_model()?;

        // Grab the newest block over RPC.
        let best_block = bitcoind.client.get_block(*newly_mined.0.first().unwrap())?;

        // Get the coinbase transaction from that block.
        let cb = best_block.coinbase().expect("coinbase missing from block");

        // Wait for a new transaction to be delivered over the subscription.
        timeout(std::time::Duration::from_secs(10), async move {
            let txid = cb.compute_txid();
            while txid
                != tx_sub
                    .next()
                    .await
                    .map(|event| event.rawtx.compute_txid())
                    .expect("stream closed before expected transaction arrived")
            {}
        })
        .await?;

        // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping
        // it earlier, aborting the producer thread.
        drop(client);

        Ok(())
    }

    // Only transactions that match the predicate are delivered (Consistency).
    #[tokio::test]
    #[serial]
    async fn only_matched_transactions_delivered() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Get a new address that we will use to send money to.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 new blocks to that same address. We use 101 so that the coins minted in the
        // first block can be spent which we will need to do for the remainder of the test.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        wait_for_height(&bitcoind, 101).await?;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // Launch a new task to issue 20 transactions paying the originally created address.
        let mine_task = tokio::task::spawn_blocking(move || {
            // Submit 20 transactions.
            for _ in 0..20 {
                bitcoind
                    .client
                    .send_to_address(&new_address, bitcoin::Amount::ONE_BTC)
                    .unwrap();
            }

            // Explicitly drop the client here to prevent rustc from "optimizing" the code and
            // dropping it earlier, aborting the producer thread. This is done in the
            // mining thread so that the subscription stream terminates.
            drop(client);
        });

        // Pull all transactions off of the subscription (until it terminates) and assert that all
        // of them pass the subscription predicate: the transactions are not a coinbase
        // transaction.
        while let Some(event) = tx_sub.next().await {
            assert!(pred(&event.rawtx))
        }

        // Wait for the mining thread to complete.
        mine_task.await?;

        Ok(())
    }

    // All transactions that match the predicate are delivered (Completeness)
    #[tokio::test]
    #[serial]
    async fn all_matched_transactions_delivered() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 blocks so that the coins in the first block are spendable.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        wait_for_height(&bitcoind, 101).await?;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        const EXPECTED_TX_COUNT: usize = 20;

        // Launch a task to issue 20 new transactions paying to the originally created address.
        // `bitcoind` is moved in to keep the node alive; `client` stays on the main task so the
        // monitoring thread isn't aborted before all events are delivered.
        let mine_task = tokio::task::spawn_blocking(move || {
            for _ in 0..EXPECTED_TX_COUNT {
                bitcoind
                    .client
                    .send_to_address(&new_address, bitcoin::Amount::ONE_BTC)
                    .unwrap();
            }
        });

        // Wait for all expected transactions to be delivered, with a timeout to guard against
        // hangs if ZMQ delivery is slower than expected.
        let mut n_tx = 0;
        let delivery_result = tokio::time::timeout(Duration::from_secs(30), async {
            while tx_sub.next().await.is_some() {
                n_tx += 1;
                if n_tx == EXPECTED_TX_COUNT {
                    return;
                }
            }
        })
        .await;

        mine_task.await?;

        assert!(
            delivery_result.is_ok(),
            "timed out waiting for transactions: received {n_tx}/{EXPECTED_TX_COUNT}"
        );
        assert_eq!(n_tx, EXPECTED_TX_COUNT);

        // `client` is dropped here, cleanly aborting the monitoring thread after all
        // expected events have been received.
        Ok(())
    }

    // Exactly one Mined status is delivered per (transaction, block) pair (Uniqueness)
    #[tokio::test]
    #[serial]
    async fn exactly_one_mined_status_per_block() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 blocks so that the coins in the first block are spendable.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        wait_for_blocks(&bitcoind.client, 101);
        let mine_height = bitcoind.client.get_block_count()?.0 + 1;
        debug!(%mine_height, "test initialized");

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // The following is a complicated list of steps wherein we will mine a transaction,
        // invalidate its block and then mine that same transaction into a new block. We
        // should get two Mined statuses for that transaction, one corresponding to each
        // time it was included in a block.
        //
        // We begin with grabbing the txid for the transaction we are interested in.
        let txid = bitcoind
            .client
            .send_to_address(&new_address, bitcoin::Amount::ONE_BTC)
            .unwrap()
            .txid()?;

        // Pull a transaction off of the subscription and assert that it is the Mempool event for
        // our transaction in question.
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.rawtx.compute_txid(), txid);
        assert_eq!(observed.status, TxStatus::Mempool);

        // Mine a block, and assert we get a Mined event for our transaction.
        let blockhash = bitcoind
            .client
            .generate_to_address(1, &new_address)
            .unwrap()
            .into_model()
            .unwrap()
            .0
            .remove(0);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.rawtx.compute_txid(), txid);
        assert_eq!(
            observed.status,
            TxStatus::Mined {
                blockhash,
                height: mine_height
            }
        );

        // Now we invalidate the block we just mined, simulating a reorg. We should now get an
        // Unknown event for that transaction as it is evicted from the landscape.
        bitcoind
            .client
            .call::<()>("invalidateblock", &[json!(blockhash.to_string())])
            .unwrap();
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.rawtx.compute_txid(), txid);
        assert_eq!(observed.status, TxStatus::Unknown);

        // Without intervention we should get a new Mempool event for our transaction as it is
        // returned to the mempool.
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.rawtx.compute_txid(), txid);
        assert_eq!(observed.status, TxStatus::Mempool);

        // Now we add a new transaction to the mempool to ensure that a new block will not exactly
        // match the one we just invalidated.
        let txid2 = bitcoind
            .client
            .send_to_address(&new_address, bitcoin::Amount::ONE_BTC)
            .unwrap()
            .txid()?;
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.rawtx.compute_txid(), txid2);
        assert_eq!(observed.status, TxStatus::Mempool);

        // Mine a new block. This should include both our original transaction and the second one we
        // created to sidestep blockhash collision.
        let blockhash = bitcoind
            .client
            .generate_to_address(1, &new_address)
            .unwrap()
            .into_model()
            .unwrap()
            .0
            .remove(0);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(
            observed.status,
            TxStatus::Mined {
                blockhash,
                height: mine_height
            }
        );
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(
            observed.status,
            TxStatus::Mined {
                blockhash,
                height: mine_height
            }
        );

        // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping
        // it earlier, aborting the producer thread.
        drop(client);

        // Assert that the stream has ended following the dropping of our zmq client.
        assert!(tx_sub.next().await.is_none());

        Ok(())
    }

    // Assuming there are no reorgs, Mined transactions are eventually buried (Eventual Finality)
    #[tokio::test]
    #[serial]
    async fn mined_txs_eventually_buried() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 blocks so that the coins in the first block are spendable.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        wait_for_height(&bitcoind, 101).await?;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // Send a non-coinbase transaction, remembering its txid.
        let txid = bitcoind
            .client
            .send_to_address(&new_address, bitcoin::Amount::ONE_BTC)
            .unwrap()
            .txid()?;

        // Kick off a mining task that will mine a new block every 100ms until we tell it to stop.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let stop_thread = stop.clone();
        let mine_task = tokio::task::spawn_blocking(move || {
            while stop_thread.load(std::sync::atomic::Ordering::SeqCst) {
                bitcoind
                    .client
                    .generate_to_address(1, &new_address)
                    .unwrap();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            drop(client);
        });

        // Continuously pull events off of the stream, checking for a Buried event for our
        // transaction.
        loop {
            if let Poll::Ready(Some(event)) = futures::poll!(tx_sub.next()) {
                // Once we receive a Buried event for our transaction we can abort the stream
                // polling and stop the mining task.
                if event.rawtx.compute_txid() == txid
                    && matches!(event.status, TxStatus::Buried { .. })
                {
                    stop.store(false, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Wait for the mining task to terminate
        tokio::time::timeout(std::time::Duration::from_secs(1), mine_task).await??;

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn dropped_tx_subscriptions_pruned() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 blocks so that the coins in the first block are spendable.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        wait_for_height(&bitcoind, 101).await?;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // Assert that we have an active transaction subscription.
        assert_eq!(client.num_tx_subscriptions().await, 1);

        // Generate a transaction that would match our filter predicate.
        let txid = bitcoind
            .client
            .send_to_address(&new_address, bitcoin::Amount::ONE_BTC)
            .unwrap()
            .txid()?;

        // Pull the Mempool event off of our subscription.
        match tx_sub.next().await {
            Some(event) => {
                assert_eq!(event.rawtx.compute_txid(), txid);
                assert_eq!(event.status, TxStatus::Mempool);
            }
            None => {
                panic!("stream wrongfully terminated by client");
            }
        }

        // Drop the subscription to trigger its removal from the BtcNotifyClient.
        drop(tx_sub);

        // Assert that we still have an active subscription because we haven't yet processed an
        // an event that would cause it prune the subscription.
        assert_eq!(client.num_tx_subscriptions().await, 1);

        // Mine a block, triggering a nominal Mined event for our active subscription, this should
        // cause the subscription to be pruned.
        bitcoind
            .client
            .generate_to_address(1, &new_address)
            .unwrap();

        // Wait for our active subscription count to report 0.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if client.num_tx_subscriptions().await == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await?;

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn dropped_block_subscriptions_pruned() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("btc-tracker");

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Create new block subscription.
        let mut block_sub = client.subscribe_blocks().await;

        // Assert that we have an active block subscription.
        assert_eq!(client.num_block_subscriptions().await, 1);

        // Generate a transaction that would match our filter predicate.
        let newly_mined = bitcoind
            .client
            .generate_to_address(1, &new_address)?
            .into_model()?;

        // Pull the Mempool event off of our subscription.
        timeout(std::time::Duration::from_secs(10), async move {
            let hash = newly_mined.0.first().expect("could not mine blocks");
            while Some(hash)
                != block_sub
                    .next()
                    .await
                    .map(|b| b.block.block_hash())
                    .as_ref()
            {}
        })
        .await?;

        // Assert that we still have an active subscription because we haven't yet processed an
        // an event that would cause it prune the subscription.
        assert_eq!(client.num_block_subscriptions().await, 1);

        // Mine a block, triggering a nominal Mined event for our active subscription, this should
        // cause the subscription to be pruned.
        bitcoind
            .client
            .generate_to_address(1, &new_address)
            .unwrap();

        // Wait for our active subscription count to report 0.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if client.num_block_subscriptions().await == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await?;

        Ok(())
    }

    proptest! {
        // run only 10 test cases
        #![proptest_config(ProptestConfig {
            cases: 10,
            .. ProptestConfig::default()
        })]

        #[test]
        #[serial]
        fn blocks_are_contiguous(
            block_batches in proptest::collection::vec(1u32..5u32, 1..5),
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                // Set up new bitcoind and zmq client instance
                let (client, bitcoind) = setup_client().await.unwrap();

                // Subscribe to new blocks
                let mut block_sub = client.subscribe_blocks().await;

                // Keep track of the last seen height
                // Since the notify service should deliver blocks starting from `start_height`, the
                // `last_height` should be one less than that.
                let mut last_height = client.start_height().saturating_sub(1);
                let new_address = bitcoind.client.new_address().unwrap();

                // Generate blocks in batches with potential gaps between batches
                for batch_size in block_batches {
                    let _ = bitcoind.client.generate_to_address(batch_size as usize, &new_address).unwrap();
                    let latest_height = bitcoind.client.get_block_count().unwrap().0;

                    let start_time = tokio::time::Instant::now();
                    // For each block in this batch
                    while last_height < latest_height {
                        if let Some(event) = timeout(Duration::from_secs(10), block_sub.next()).await.unwrap() {
                            match event.status {
                                BlockStatus::Uncled => continue,
                                BlockStatus::Buried => continue,
                                BlockStatus::Mined => {
                                    let received_height = event.block.bip34_block_height().unwrap();

                                    // Verify that this block's height is exactly one more than the last seen height
                                    prop_assert_eq!(
                                        received_height,
                                        last_height + 1,
                                        "Block heights should be contiguous. Expected height {}, got {}",
                                        last_height + 1,
                                        received_height
                                    );

                                    last_height = received_height;
                                },
                            }
                        }

                        prop_assert!(start_time.elapsed() < Duration::from_secs(300), "timeout waiting for block events");
                    }
                }

                // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping
                // it earlier, aborting the producer thread
                drop(client);

                Ok::<(), proptest::test_runner::TestCaseError>(())
            })
            .unwrap();
        }
    }
}
