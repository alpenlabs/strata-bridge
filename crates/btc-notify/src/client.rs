//! This module contains the top level BtcZmqClient implementation.
//!
//! Once the client is initialized, consumers of this API will create [`Subscription`]s with
//! [`BtcZmqClient::subscribe_blocks`] or [`BtcZmqClient::subscribe_transactions`]. These
//! subscription objects can be primarily worked with via their [`futures::Stream`] trait API.
use std::{collections::VecDeque, error::Error, sync::Arc, time::Duration};

use algebra::{category, predicate};
use bitcoin::{Block, Transaction};
use bitcoincore_zmq::{subscribe_async_wait_handshake, Message, SocketMessage};
use futures::{future, Stream, StreamExt};
use tokio::{
    sync::{mpsc, Mutex},
    task::{self, JoinHandle},
};
use tracing::{debug, error, info, trace, warn};

pub use crate::{
    config::BtcZmqConfig,
    event::{BlockEvent, BlockStatus, TxEvent, TxStatus},
    state_machine::TxPredicate,
};
use crate::{state_machine::BtcZmqSM, subscription::Subscription};

struct TxSubscriptionDetails {
    predicate: TxPredicate,
    outbox: mpsc::UnboundedSender<TxEvent>,
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
/// After construction, this object must be kept around for the monitoring process to continue.
/// Dropping this object will abort the monitoring thread.
#[derive(Debug, Clone)]
pub struct BtcZmqClient {
    bury_depth: usize,
    block_subs: Arc<Mutex<Vec<mpsc::UnboundedSender<BlockEvent>>>>,
    tx_subs: Arc<Mutex<Vec<TxSubscriptionDetails>>>,
    state_machine: Arc<Mutex<BtcZmqSM>>,
    thread_handle: Arc<JoinHandle<()>>,
}

impl Drop for BtcZmqClient {
    fn drop(&mut self) {
        self.thread_handle.abort();
    }
}

impl BtcZmqClient {
    /// Primary constructor for [`BtcZmqClient`].
    ///
    /// It takes a [`BtcZmqConfig`] and uses that information to connect to `bitcoind`. The second
    /// argument is the list of unburied blocks. It is assumed that the length of this queue is the
    /// same as the `bury_depth` in the config and it is assumed that all of the blocks in this
    /// queue are the most recent ones in the main chain.
    pub async fn connect(
        cfg: &BtcZmqConfig,
        unburied_blocks: VecDeque<Block>,
    ) -> Result<Self, Box<dyn Error>> {
        trace!(?cfg, "subscribing to bitcoind");

        let sockets = cfg
            .hashblock_connection_string
            .iter()
            .chain(cfg.hashtx_connection_string.iter())
            .chain(cfg.rawblock_connection_string.iter())
            .chain(cfg.rawtx_connection_string.iter())
            .chain(cfg.sequence_connection_string.iter())
            .map(String::as_str)
            .collect::<Vec<&str>>();

        let mut stream = match tokio::time::timeout(
            Duration::from_millis(2000),
            subscribe_async_wait_handshake(&sockets),
        )
        .await
        {
            Ok(Ok(stream)) => {
                // Ok(Ok(_)), ok from both functions.
                stream
            }
            Ok(Err(err)) => {
                // Ok(Err(_)), ok from `timeout` but an error from the subscribe function.
                panic!("subscribe error: {err}");
            }
            Err(_) => {
                // Err(_), err from `timeout` means that it timed out.
                panic!("bitcoin-core zmq subscription handshake timed out");
            }
        };

        let state_machine = Arc::new(Mutex::new(BtcZmqSM::init(cfg.bury_depth, unburied_blocks)));
        let block_subs = Arc::new(Mutex::new(Vec::<mpsc::UnboundedSender<BlockEvent>>::new()));
        let block_subs_thread = block_subs.clone();
        let tx_subs = Arc::new(Mutex::new(Vec::<TxSubscriptionDetails>::new()));
        let tx_subs_thread = tx_subs.clone();
        let state_machine_thread = state_machine.clone();
        let thread_handle = Arc::new(task::spawn(async move {
            loop {
                // This loop has no break condition. It is only aborted when the BtcZmqClient is
                // dropped.
                info!("listening for ZMQ events");

                while let Some(res) = stream.next().await {
                    let mut sm = state_machine_thread.lock().await;
                    let diff = match res {
                        Ok(SocketMessage::Message(msg)) => {
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
                                    // First send the block to the block subscribers.
                                    // if the receiver has been dropped, we remove it from the
                                    // subscription list.
                                    block_subs_thread.lock().await.retain(|sub| {
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
                                        block_subs_thread
                                            .lock()
                                            .await
                                            .retain(|sub| sub.send(block_event.clone()).is_ok())
                                    }
                                    tx_events
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
                                        block_subs_thread
                                            .lock()
                                            .await
                                            .retain(|sub| sub.send(block_event.clone()).is_ok());
                                    }

                                    tx_events
                                }
                            }
                        }
                        Ok(monitoring_msg) => {
                            warn!(?monitoring_msg, "ignoring monitoring message");
                            Vec::new()
                        }
                        Err(e) => {
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
            }
        }));

        info!("subscribed to bitcoind");

        Ok(BtcZmqClient {
            bury_depth: cfg.bury_depth,
            block_subs,
            tx_subs,
            state_machine,
            thread_handle,
        })
    }

    /// Creates a new [`Subscription`] that emits new [`bitcoin::Transaction`] and [`TxStatus`]
    /// every time a transaction's status changes due to block or mempool events.
    pub async fn subscribe_transactions(
        &self,
        f: impl Fn(&Transaction) -> bool + Sync + Send + 'static,
    ) -> impl Stream<Item = TxEvent> {
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
    pub async fn subscribe_blocks(&self, first: u64) -> impl Stream<Item = BlockEvent> {
        let (send, recv) = mpsc::unbounded_channel::<BlockEvent>();

        trace!("subscribing to blocks");

        self.block_subs.lock().await.push(send);

        Subscription::from_receiver(recv).skip_while(move |evt| {
            future::ready(
                evt.block
                    .bip34_block_height()
                    .map(category::moved(predicate::lt(first)))
                    .unwrap_or(true),
            )
        })
    }

    /// Returns the number of active transaction subscriptions created with
    /// [`BtcZmqClient::subscribe_transactions`].
    pub async fn num_tx_subscriptions(&self) -> usize {
        self.tx_subs.lock().await.len()
    }

    /// Returns the number of active block subscriptions created with
    /// [`BtcZmqClient::subscribe_blocks`].
    pub async fn num_block_subscriptions(&self) -> usize {
        self.block_subs.lock().await.len()
    }

    /// Returns the configured [`BtcZmqConfig::with_bury_depth`].
    pub const fn bury_depth(&self) -> usize {
        self.bury_depth
    }
}

#[cfg(test)]
mod e2e_tests {
    use std::task::Poll;

    use corepc_node::serde_json::json;
    use serial_test::serial;
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_test_utils::prelude::{wait_for_blocks, wait_for_height};
    use tokio::time::timeout;

    use super::*;
    use crate::{constants::DEFAULT_BURY_DEPTH, event::TxStatus, state_machine::BIP34_MIN_HEIGHT};

    async fn setup_node() -> Result<(BtcZmqConfig, corepc_node::Node), Box<dyn std::error::Error>> {
        let mut bitcoin_conf = corepc_node::Conf::default();
        bitcoin_conf.enable_zmq = true;

        // TODO(proofofkeags): do dynamic port allocation so these can be run in parallel
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
        // NOTE(proofofkeags): for some reason it appears that ZMQ flushes every 5 blocks, or
        // perhaps after a certain number of bytes. This means that even though we should be able to
        // handle everything after [`crate::BIP34_MIN_HEIGHT`], we can't just simply waight for that
        // height since old blocks are still buffered in the zmq socket. It appears to update its
        // internal cursor at block heights 1, 6, 11, 16, and 21. 21 Is the first one that actually
        // works due to BIP34 requirements.
        bitcoind
            .client
            .generate_to_address(BIP34_MIN_HEIGHT as usize, &address)?;
        wait_for_height(&bitcoind, BIP34_MIN_HEIGHT as usize).await?;

        let cfg = BtcZmqConfig::default()
            .with_bury_depth(DEFAULT_BURY_DEPTH)
            .with_hashblock_connection_string(hash_block_socket)
            .with_hashtx_connection_string(hash_tx_socket)
            .with_rawblock_connection_string(raw_block_socket)
            .with_rawtx_connection_string(raw_tx_socket)
            .with_sequence_connection_string(sequence_socket);

        Ok((cfg, bitcoind))
    }

    async fn setup_client() -> Result<(BtcZmqClient, corepc_node::Node), Box<dyn std::error::Error>>
    {
        let (cfg, bitcoind) = setup_node().await?;

        let client = BtcZmqClient::connect(&cfg, VecDeque::new()).await?;

        Ok((client, bitcoind))
    }

    async fn setup_two_clients(
    ) -> Result<(BtcZmqClient, BtcZmqClient, corepc_node::Node), Box<dyn std::error::Error>> {
        let (cfg, bitcoind) = setup_node().await?;

        info!("connecting to bitcoind with client 1");
        let client_1 = BtcZmqClient::connect(&cfg, VecDeque::new()).await?;
        info!("connecting to bitcoind with client 2");
        let client_2 = BtcZmqClient::connect(&cfg, VecDeque::new()).await?;

        Ok((client_1, client_2, bitcoind))
    }

    #[tokio::test]
    #[serial]
    async fn basic_subscribe_blocks_functionality() -> Result<(), Box<dyn std::error::Error>> {
        logging::init(LoggerConfig::new("btc-notify".to_string()));

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Subscribe to new blocks
        let mut block_sub = client.subscribe_blocks(BIP34_MIN_HEIGHT).await;

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
        logging::init(LoggerConfig::new("btc-notify".to_string()));

        info!("setting up two clients");
        let (client_1, client_2, bitcoind) = setup_two_clients().await?;
        info!("subscribing to blocks");

        let mut block_sub_1 = client_1.subscribe_blocks(BIP34_MIN_HEIGHT).await;
        let mut block_sub_2 = client_2.subscribe_blocks(BIP34_MIN_HEIGHT).await;

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

        if newly_mined.0.first() != blk_1.as_ref() && newly_mined.0.first() != blk_2.as_ref() {
            // TODO(proofokeags): to fix this we actually need to implement a cursor height into the
            // block subscription call so we skip stale events. At the moment we don't have enough
            // control over where the ZMQ stream begins so we need to implement that control in the
            // client itself if this becomes a requirement.
            warn!("newly mined block is not the same as the first ZMQ socket event");
        }
        assert_eq!(blk_1.as_ref(), blk_2.as_ref());

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
        logging::init(LoggerConfig::new("btc-notify".to_string()));

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
        logging::init(LoggerConfig::new("btc-notify".to_string()));

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
        logging::init(LoggerConfig::new("btc-notify".to_string()));

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

        // Launch a task to issue 20 new transactions paying to the originally created address.
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

        // Count all of the transactions that come over the subscription, waiting for the
        // subscription to terminate.
        let mut n_tx = 0;
        while tx_sub.next().await.is_some() {
            n_tx += 1;
        }

        // Wait for the mining task to complete.
        mine_task.await?;

        // Assert that we received all 20 transactions over with a Mempool and Mined status for
        // each.
        assert_eq!(n_tx, 20);

        Ok(())
    }

    // Exactly one Mined status is delivered per (transaction, block) pair (Uniqueness)
    #[tokio::test]
    #[serial]
    async fn exactly_one_mined_status_per_block() -> Result<(), Box<dyn std::error::Error>> {
        logging::init(LoggerConfig::new("btc-notify".to_string()));

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
        logging::init(LoggerConfig::new("btc-notify".to_string()));

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
        logging::init(LoggerConfig::new("btc-notify".to_string()));

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

        // Drop the subscription to trigger its removal from the BtcZmqClient.
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
        logging::init(LoggerConfig::new("btc-notify".to_string()));

        // Set up new bitcoind and zmq client instance.
        let (client, bitcoind) = setup_client().await?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Create new block subscription.
        let mut block_sub = client.subscribe_blocks(BIP34_MIN_HEIGHT).await;

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
}
