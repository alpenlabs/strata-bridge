use bitcoin::transaction::Transaction;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Txid;
use bitcoincore_zmq::Message;
use bitcoincore_zmq::SequenceMessage;
use futures::Stream;
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::error::Error;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

/// BtcZmqConfig is the main configuration type used to establish the connection with the ZMQ interface of Bitcoin. It
/// accepts independent connection strings for each of the stream types. Any connection strings that are left as None
/// when initializing the BtcZmqClient will result in those streams going unmonitored. In the limit, this means that the
/// default BtcZmqConfig will result in a BtcZmqClient that does absolutely nothing (NOOP).
#[derive(Debug, Clone)]
pub struct BtcZmqConfig {
    /// depth at which a transaction is considered buried, defaults to 6
    bury_depth: usize,

    /// connection string used in bitcoin.conf => zmqpubhashblock
    hashblock_connection_string: Option<String>,

    /// connection string used in bitcoin.conf => zmqpubhashtx
    hashtx_connection_string: Option<String>,

    /// connection string used in bitcoin.conf => zmqpubrawblock
    rawblock_connection_string: Option<String>,

    /// connection string used in bitcoin.conf => zmqpubrawtx
    rawtx_connection_string: Option<String>,

    /// connection string used in bitcoin.conf => zmqpubsequence
    sequence_connection_string: Option<String>,
}

impl BtcZmqConfig {
    /// This generates a default config that will not connect to any of the bitcoind zeromq interfaces. It is useful in
    /// conjunction with subsequent mutations for partial initialization.
    pub fn empty() -> BtcZmqConfig {
        BtcZmqConfig {
            bury_depth: 6,
            hashblock_connection_string: None,
            hashtx_connection_string: None,
            rawblock_connection_string: None,
            rawtx_connection_string: None,
            sequence_connection_string: None,
        }
    }

    /// Updates the BtcZmqConfig with a zmqpubhashblock connection string and returns the updated config. Useful for a
    /// builder pattern with dotchaining.
    pub fn with_hashblock_connection_string(mut self, s: &str) -> Self {
        self.hashblock_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubhashtx connection string and returns the updated config. Useful for a
    /// builder pattern with dotchaining.
    pub fn with_hashtx_connection_string(mut self, s: &str) -> Self {
        self.hashtx_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubrawblock connection string and returns the updated config. Useful for a
    /// builder pattern with dotchaining.
    pub fn with_rawblock_connection_string(mut self, s: &str) -> Self {
        self.rawblock_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubrawtx connection string and returns the updated config. Useful for a
    /// builder pattern with dotchaining.
    pub fn with_rawtx_connection_string(mut self, s: &str) -> Self {
        self.rawtx_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a zmqpubsequence connection string and returns the updated config. Useful for a
    /// builder pattern with dotchaining.
    pub fn with_sequence_connection_string(mut self, s: &str) -> Self {
        self.sequence_connection_string = Some(s.to_string());
        self
    }

    /// Updates the BtcZmqConfig with a new bury depth and returns the updated config. Useful for a builder pattern with
    /// dotchaining. Note, this is the number of blocks that must be built on top of a given block before that block is
    /// considered buried. A bury depth of 6 will mean that the most recent "buried" block will be the 7th newest block.
    /// A bury depth of 0 would mean that the block is considered buried the moment it is mined.
    pub fn with_bury_depth(mut self, n: usize) -> Self {
        self.bury_depth = n;
        self
    }
}

/// TxStatus is the primary output of this API via the subscription.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxStatus {
    /// Unknown indicates that the transaction is not staged for inclusion in the blockchain. Concretely this status
    /// will only really appear if the transaction is evicted from the mempool.
    Unknown,
    /// Mempool indicates that the transaction is currently in the mempool. This status will be emitted both when a
    /// transaction enters the mempool for the first time as well as if it re-enters the mempool due to a containing
    /// block get reorg'ed out of the main chain and not yet included in the alternative one.
    Mempool,
    /// Mined indicates that the transaction has been included in a block. This status will be received once per
    /// transaction per block. If a transaction is included in a block, and then that block is reorg'ed out and the same
    /// transaction is included in a new block, then the subscription will emit two separate events for it.
    Mined,
    /// Buried is a terminal status. It will be emitted once the transaction's containing block has been buried under
    /// a sufficient number of subsequent blocks. After this status is emitted, no further statuses for that transaction
    /// will be emitted.
    Buried
}

/// This structure serves as the primary type that consumers of this API will handle. It is created via one of the calls
/// to BtcZmqClient::subscribe_*. From there you should use it via it's Stream API.
#[derive(Debug)]
pub struct Subscription<T> {
    receiver: mpsc::UnboundedReceiver<T>,
}

impl<T> Subscription<T> {
    /// Intentionally left private so as not to leak implementation details to consuming APIs.
    fn from_receiver(receiver: mpsc::UnboundedReceiver<T>) -> Subscription<T> {
        Subscription {
            receiver,
        }
    }
}

impl<T> Stream for Subscription<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().receiver.poll_recv(cx)
    }
}

/// This is a type synonym to capture predicates of the following form: Transaction -> bool
/// The choice of using an arc here is intentional so that we can directly compare these predicates when managing the
/// active subscription set.
type TxPredicate = Arc<dyn Fn(&Transaction) -> bool + Sync + Send>;

struct TxSubscriptionDetails {
    predicate: TxPredicate,
    outbox: mpsc::UnboundedSender<(Transaction, TxStatus)>,
}
impl std::fmt::Debug for TxSubscriptionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxSubscriptionDetails")
            .field("predicate", &format!("{:?}", Arc::as_ptr(&self.predicate)))
            .field("outbox", &self.outbox).finish()
    }
}

#[derive(Debug)]
pub struct BtcZmqClient {
    block_subs: Arc<Mutex<Vec<mpsc::UnboundedSender<Block>>>>,
    tx_subs: Arc<Mutex<Vec<TxSubscriptionDetails>>>,
    state_machine: Arc<Mutex<BtcZmqSM>>,
    thread_handle: JoinHandle<()>,
}

impl Drop for BtcZmqClient {
    fn drop(&mut self) {
        self.thread_handle.abort();
    }
}

impl BtcZmqClient {
    pub fn connect(cfg: BtcZmqConfig) -> Result<Self, Box<dyn Error>> {
        let state_machine = Arc::new(Mutex::new(BtcZmqSM::init(cfg.bury_depth)));

        let sockets = cfg.hashblock_connection_string.iter()
            .chain(cfg.hashtx_connection_string.iter())
            .chain(cfg.rawblock_connection_string.iter())
            .chain(cfg.rawtx_connection_string.iter())
            .chain(cfg.sequence_connection_string.iter())
            .map(String::as_str)
            .collect::<Vec<&str>>();

        let mut stream = bitcoincore_zmq::subscribe_async(&sockets)?;

        let block_subs = Arc::new(Mutex::new(Vec::<mpsc::UnboundedSender<Block>>::new()));
        let block_subs_thread = block_subs.clone();
        let tx_subs = Arc::new(Mutex::new(Vec::<TxSubscriptionDetails>::new()));
        let tx_subs_thread = tx_subs.clone();
        let state_machine_thread = state_machine.clone();
        let thread_handle = tokio::task::spawn(async move {
            loop {
                while let Some(res) = stream.next().await {
                    let mut sm = state_machine_thread.lock().await;
                    let diff = match res {
                        Ok(Message::HashBlock(_, _)) => { Vec::new() }
                        Ok(Message::HashTx(_, _)) => { Vec::new() }
                        Ok(Message::Block(block, _)) => {
                            // First send the block to the block subscribers.
                            block_subs_thread.lock().await.retain(|sub| sub.send(block.clone()).is_ok());

                            // Now we process the block to understand what the relevant transaction diff is.
                            sm.process_block(block)
                        },
                        Ok(Message::Tx(tx, _)) => sm.process_tx(tx),
                        Ok(Message::Sequence(seq, _)) => sm.process_sequence(seq),
                        Err(e) => {
                            eprintln!("ERROR: {e:?}");
                            Vec::new()
                        }
                    };
                    // Now we send the diff to the relevant subscribers. If we ever encounter a send error, it
                    // means the receiver has been dropped.
                    tx_subs_thread.lock().await.retain(|sub| {
                        for msg in diff.iter().filter(|(tx, _)| (sub.predicate)(tx)) {
                            if sub.outbox.send(msg.clone()).is_err() {
                                sm.rm_filter(&sub.predicate);
                                return false
                            }
                        }
                        true
                    });
                }
            }
        });

        Ok(BtcZmqClient {
            block_subs,
            tx_subs,
            state_machine,
            thread_handle,
        })
    }

    pub async fn subscribe_transactions(&mut self, f: impl Fn(&Transaction) -> bool + Sync + Send + 'static) ->
        Subscription<(Transaction, TxStatus)> {

        let (send, recv) = mpsc::unbounded_channel();

        let details = TxSubscriptionDetails {
            predicate: Arc::new(f),
            outbox: send,
        };

        let mut subs = self.tx_subs.lock().await;
        let mut sm = self.state_machine.lock().await;
        sm.add_filter(details.predicate.clone());
        subs.push(details);

        Subscription::from_receiver(recv)
    }

    pub async fn subscribe_blocks(&mut self) -> Subscription<Block> {
        let (send, recv) = mpsc::unbounded_channel();

        self.block_subs.lock().await.push(send);

        Subscription::from_receiver(recv)
    }

    pub async fn num_tx_subscriptions(&self) -> usize {
        self.tx_subs.lock().await.len()
    }

    pub async fn num_block_subscriptions(&self) -> usize {
        self.block_subs.lock().await.len()
    }
}

/// This structure is here so that we can keep track of messages coming in on parallel streams that are all
/// tracking the same underlying event. Depending on the messages we receive and in what order we track the transaction
/// all the way to block inclusion, inferring other states depending on the messages we have received.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TxLifecycle {
    raw: Transaction,
    block: Option<BlockHash>,
}

/// This is the pure state machine that processes all the relevant messages. From there it will emit diffs that describe
/// the new states of transactions.
#[derive(Clone)]
struct BtcZmqSM {
    /// This is the number of subsequent blocks that must be built on top of a given block for that block to be
    /// considered "buried": the transactions will never be reversed.
    bury_depth: usize,

    /// This is the set of predicates that are selecting for transactions, the disjunction of which we care about.
    tx_filters: Vec<TxPredicate>,

    /// This is the core data structure that holds TxLifecycles indexed by txid. The encoding should be understood as
    /// follows: If the entry is in the map but the value is None, then it means we have only received the
    /// MempoolAcceptance event. If it's present then we will definitely have the rawtx event, and if it has been mined
    /// into a block, we will also have that blockhash as well.
    tx_lifecycles: BTreeMap<Txid, Option<TxLifecycle>>,

    // We track the list of unburied blocks in a queue where the front is the newest block and the back is the oldest
    // "unburied" block
    unburied_blocks: VecDeque<Block>,
}
impl std::fmt::Debug for BtcZmqSM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcZmqSM")
            .field("bury_depth", &self.bury_depth)
            .field("tx_filters", &self.tx_filters.iter().map(|f| format!("{:?}", Arc::as_ptr(f))).collect::<Vec<String>>())
            .field("tx_lifecycles", &self.tx_lifecycles)
            .field("unburied_blocks", &self.unburied_blocks)
            .finish()
    }
}
impl PartialEq for BtcZmqSM {
    fn eq(&self, other: &Self) -> bool {
        let filter_eq = self.tx_filters.len() == other.tx_filters.len() &&
            self.tx_filters.iter().zip(other.tx_filters.iter()).all(|(a, b)| Arc::ptr_eq(a, b));

        filter_eq &&
            self.bury_depth == other.bury_depth &&
            self.tx_lifecycles == other.tx_lifecycles &&
            self.unburied_blocks == other.unburied_blocks
    }
}
impl Eq for BtcZmqSM {}

impl BtcZmqSM {
    // init initializes a BtcZmqSM with the supplied bury_depth. bury_depth is the number of blocks that must be built
    // on top of a given block before that block's transactions are considered Buried.
    fn init(bury_depth: usize) -> Self {
        BtcZmqSM {
            bury_depth,
            tx_filters: Vec::new(),
            tx_lifecycles: BTreeMap::new(),
            unburied_blocks: VecDeque::new(),
        }
    }

    // add_filter takes a tx predicate and adds it to the state machine. The state machine will track any transaction
    // that matches the disjunction of predicates added.
    fn add_filter(&mut self, pred: TxPredicate) {
        self.tx_filters.push(pred);
    }

    // rm_filter takes a TxPredicate that was previously added via add_filter.
    fn rm_filter(&mut self, pred: &TxPredicate) {
        if let Some(idx) = self.tx_filters.iter().position(|p| Arc::ptr_eq(p, pred)) {
            self.tx_filters.swap_remove(idx);
        }
    }

    // process_block is one of the three primary state transition functions of the BtcZmqSM, updating internal state to
    // reflect the contents of the block.
    fn process_block(&mut self, block: Block) -> Vec<(Transaction, TxStatus)> {
        match self.unburied_blocks.front() {
            Some(tip) => {
                if block.header.prev_blockhash == tip.block_hash() {
                    self.unburied_blocks.push_front(block)
                } else {
                    // This implies that we missed a block.
                    //
                    // TODO(proofofkeags): It's also possible that race conditions in the concurrent stream processing
                    // would cause this to fire during a reorg. Race conditions MUST NOT cause this to fire. This MUST
                    // be fixed.
                    panic!("invariant violated: blocks received out of order");
                }
            }
            // TODO(proofofkeags): fix the problem where we can't notice reorgs close to startup time
            // This is due to the fact that we don't have a full bury depth of history. Fixing this requires us to
            // backfill the block history at startup using the RPC interface, or accepting the blocks newer than the
            // bury depth as an argument to the constructor.
            None => {
                self.unburied_blocks.push_front(block)
            }
        }
        let block = self.unburied_blocks.front().unwrap();

        // Now we allocate a Vec will collect the net-new transaction states that need to be distributed.
        let mut diff = Vec::new();

        // When a block is processed, it implicitly means that this is the tip. Even in the case of large fork reorgs
        // each block will be added as the tip in order so we will get all events. When a block is mined, it will cause
        // three types of state transitions:
        // 1. Unknown -> Mined
        // 2. Mempool -> Mined
        // 3. Mined -> Buried
        for matched_tx in block.txdata.iter().filter(|tx| self.tx_filters.iter().any(|f| f(tx))) {
            match self.tx_lifecycles.get_mut(&matched_tx.compute_txid()) {
                // This is either the scenario where we haven't yet seen the transaction in any capacity, or where we
                // have a MempoolAcceptance event for it but no other information on it. In either case we handle it the
                // same way, recording the rawtx data in a TxLifecycle and its containing block hash, as well as adding
                // a Mined transaction event to the diff.
                None | Some(None) => {
                    let lifecycle = TxLifecycle {
                        // TODO(proofofkeags): figure out how to make this a reference into the block we save to avoid
                        // duplicating transaction data.
                        raw: matched_tx.clone(),
                        block: Some(block.block_hash()),
                    };
                    self.tx_lifecycles.insert(matched_tx.compute_txid(), Some(lifecycle));
                    diff.push((matched_tx.clone(), TxStatus::Mined));
                }
                // This means we have seen the rawtx event for this transaction before.
                Some(Some(lifecycle)) => {
                    let blockhash = block.block_hash();
                    if let Some(prior_blockhash) = lifecycle.block {
                        // This means that it was previously mined. This is pretty weird and so we include some debug
                        // assertions to rule out violations in our core assumptions.
                        debug_assert!(*matched_tx == lifecycle.raw, "transaction data mismatch");
                        debug_assert!(prior_blockhash != blockhash, "duplicate block message");
                    }

                    // Record the update and add it to the diff.
                    lifecycle.block = Some(blockhash);
                    diff.push((matched_tx.clone(), TxStatus::Mined));
                }
            }
        }

        if self.unburied_blocks.len() > self.bury_depth {
            if let Some(newly_buried) = self.unburied_blocks.pop_back() {
                // Now that we've handled the Mined transitions. We can take the oldest block we are still tracking and
                // declare all of its relevant transactions buried, and then finally we can clear the buried
                // transactions from the current lifecycle map.
                for buried_tx in newly_buried.txdata {
                    self.tx_lifecycles.remove(&buried_tx.compute_txid());
                    if self.tx_filters.iter().any(|f|f(&buried_tx)) {
                        diff.push((buried_tx, TxStatus::Buried));
                    }
                }
            }
        }

        diff
    }

    // process_tx is one of the three primary state transition functions of the BtcZmqSM, updating internal state to
    // reflect the contents of the transaction.
    fn process_tx(&mut self, tx: Transaction) -> Vec<(Transaction, TxStatus)> {
        if !self.tx_filters.iter().any(|f|f(&tx)) {
            return Vec::new();
        }

        let txid = tx.compute_txid();
        let lifecycle = self.tx_lifecycles.get_mut(&txid);
        match lifecycle {
            // In this case we have never seen any information on this transaction whatsoever.
            None => {
                let lifecycle = TxLifecycle {
                    raw: tx,
                    block: None,
                };

                self.tx_lifecycles.insert(txid, Some(lifecycle));

                // We intentionally DO NOT return the transaction here in the diff because we are unsure of what the
                // status is. We will either immediately get a followup block or a followup sequence which will cause us
                // to emit a new state change.
                Vec::new()
            }
            // In this case we have seen a MempoolAcceptance event for this txid, but haven't seen the actual
            // transaction data yet.
            Some(None) => {
                let lifecycle = TxLifecycle {
                    raw: tx.clone(),
                    block: None,
                };

                self.tx_lifecycles.insert(txid, Some(lifecycle));

                // Presence within the map indicates we have already received the sequence message for this but don't
                // yet have any other information, indicating that this rawtx event can generate the Mempool event.
                vec![(tx, TxStatus::Mempool)]
            }
            // In this case we know everything we need to about this transaction, and this is probably a rawtx event
            // that accompanies an upcoming new block event.
            Some(Some(_)) => Vec::new(),
        }
    }

    // process_sequence is one of the three primary state transition functions of the BtcZmqSM, updating internal state
    // to reflect the sequence event.
    fn process_sequence(&mut self, seq: SequenceMessage) -> Vec<(Transaction, TxStatus)> {
        let mut diff = Vec::new();
        match seq {
            SequenceMessage::BlockConnect { .. } => { /* NOOP */ },
            SequenceMessage::BlockDisconnect { blockhash } => {
                // If the block is disconnected we reset all transactions that currently have that blockhash as their
                // containing block.
                if let Some(block) = self.unburied_blocks.front() {
                    if block.block_hash() == blockhash {
                        self.unburied_blocks.pop_front();
                    } else {
                        // As far as I can tell, the block connect and diconnect events are done in "stack order". This
                        // means that block connects happen in chronological order and disconnects happen in reverse
                        // chronological order. If we get a block disconnect event that doesn't match our current tip
                        // then this assumption has broken down.
                        panic!("invariant violated: out of order block disconnect");
                    }
                }

                // Clear out all of the transactions we are tracking that were bound to the disconnected block.
                self.tx_lifecycles.retain(|_, v| {
                    match v {
                        Some(lifecycle) => match lifecycle.block {
                            // Only clear the tx if its blockhash matches the blockhash of the disconnected block.
                            Some(blk) if blk == blockhash => {
                                diff.push((lifecycle.raw.clone(), TxStatus::Unknown));
                                false
                            }
                            // Otherwise keep it.
                            _ => true,
                        }
                        None => true,
                    }
                });
            }
            SequenceMessage::MempoolAcceptance { txid, .. } => {
                match self.tx_lifecycles.get_mut(&txid) {
                    // In this case we are well aware of the full transaction data here
                    Some(Some(lifecycle)) => {
                        match lifecycle.block {
                            // This will happen if we receive rawtx before MempoolAcceptance.
                            None => { diff = vec![(lifecycle.raw.clone(), TxStatus::Mempool)]; },
                            // This should never happen.
                            Some(_) => panic!("invariant violated: mempool acceptance after mining"),
                        }
                    }
                    // In this case we have received a MempoolAcceptance event for this txid, but haven't yet processed
                    // the accompanying rawtx event.
                    //
                    // TODO(proofofkeags): relax this. In theory it should never happen but I don't think it
                    // is a material issue if we do. This is currently a panic to allow us to quickly discover
                    // if this assumption doesn't hold and what it means
                    Some(None) => panic!("invariant violated: duplicate mempool acceptance"),
                    // In this case we know nothing of this transaction yet.
                    None => {
                        // We insert a placeholder because we expect the rawtx event to fill in the remainder of the
                        // details.
                        //
                        // NOTE(proofofkeags): since we don't have the raw tx yet we can't check for predicate matches
                        // so this will actually leak memory until we clear out these placeholders. However, for every
                        // MempoolAcceptance event we are guaranteed to have a corresponding rawtx event. So this
                        // shouldn't cause a memory leak unless we miss ZMQ events entirely.
                        self.tx_lifecycles.insert(txid, None);
                    }
                }
            }
            SequenceMessage::MempoolRemoval { txid, .. } => {
                match self.tx_lifecycles.remove(&txid) {
                    // This will happen if we've seen the rawtx event for a txid irrespective of its MempoolAcceptance.
                    //
                    // There is an edge case here that will leak memory. The scenario that can cause this is
                    // when we receive a MempoolAcceptance, MempoolRemoval, then the rawtx. The only scenario where I
                    // can picture this happening is during mempool replacement cycling attacks. Even then though it
                    // relies on a specific ordering of events to leak memory. This order of events is possible given
                    // the guarantees of Bitcoin Core's ZMQ interface, but seems unlikely due to real world timings
                    // and the behavior of the ZMQ streams.
                    //
                    // For now I think we can leave this alone, but if we notice memory leaks in a live deployment
                    // this will be one of the places to look.
                    Some(Some(lifecycle)) => {
                        diff = vec![(lifecycle.raw, TxStatus::Unknown)];
                    }
                    // This will happen if we've only received a MempoolAcceptance event, the removal will cancel it
                    // fully.
                    Some(None) => { /* NOOP */ }
                    // This happens if we've never heard anything about this transaction before.
                    None => { /* NOOP */ }
                }
            }
        }

        diff
    }
}

#[cfg(test)]
mod e2e_tests {
    use corepc_node::serde_json;
    use serial_test::serial;

    use super::*;

    fn setup() -> Result<(BtcZmqClient, corepc_node::Node), Box<dyn std::error::Error>> {
        let mut bitcoin_conf = corepc_node::Conf::default();
        bitcoin_conf.view_stdout = false;
        bitcoin_conf.enable_zmq = true;
        // TODO(proofofkeags): do dynamic port allocation so these can be run in parallel
        bitcoin_conf.args.extend(vec![
            "-zmqpubhashblock=tcp://127.0.0.1:23882",
            "-zmqpubhashtx=tcp://127.0.0.1:23883",
            "-zmqpubrawblock=tcp://127.0.0.1:23884",
            "-zmqpubrawtx=tcp://127.0.0.1:23885",
            "-zmqpubsequence=tcp://127.0.0.1:23886",
            "-debug=zmq",
        ]);
        let bitcoind = corepc_node::Node::from_downloaded_with_conf(&bitcoin_conf)?;

        let cfg = BtcZmqConfig::empty()
            .with_hashblock_connection_string("tcp://127.0.0.1:23882")
            .with_hashtx_connection_string("tcp://127.0.0.1:23883")
            .with_rawblock_connection_string("tcp://127.0.0.1:23884")
            .with_rawtx_connection_string("tcp://127.0.0.1:23885")
            .with_sequence_connection_string("tcp://127.0.0.1:23886");

        let client = BtcZmqClient::connect(cfg)?;

        Ok((client, bitcoind))
    }

    #[tokio::test]
    #[serial]
    async fn basic_subscribe_blocks_functionality() -> Result<(), Box<dyn std::error::Error>> {
        // Set up new bitcoind and zmq client instance
        let (mut client, mut bitcoind) = setup()?;

        // Subscribe to new blocks
        let mut block_sub = client.subscribe_blocks().await;

        // Mine a new block
        let newly_mined = bitcoind.client.generate_to_address(1, &bitcoind.client.new_address()?)?.into_model()?;

        // Wait for a new block to be delivered over the subscription
        let blk = block_sub.next().await.map(|b|b.block_hash());

        // Assert that these blocks are equal
        assert_eq!(newly_mined.0.first(), blk.as_ref());

        // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping it earlier, aborting
        // the producer thread
        drop(client);

        bitcoind.stop()?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn basic_subscribe_transactions_functionality() -> Result<(), Box<dyn std::error::Error>> {
        // Set up new bitcoind and zmq client instance.
        let (mut client, mut bitcoind) = setup()?;

        // Subscribe to all transactions.
        let mut tx_sub = client.subscribe_transactions(|_|true).await;

        // Mine a new block.
        let newly_mined = bitcoind.client.generate_to_address(1, &bitcoind.client.new_address()?)?.into_model()?;

        // Wait for a new transaction to be delivered over the subscription.
        let tx = tx_sub.next().await.map(|(tx, _)|tx.compute_txid());

        // Grab the newest block ofver RPC.
        let best_block = bitcoind.client.get_block(*newly_mined.0.first().unwrap())?;

        // Get the coinbase transaction from that block.
        let cb = best_block.coinbase();

        // Assert that the tx delivered earlier matches this block's coinbase transaction.
        assert_eq!(tx, cb.map(|cb|cb.compute_txid()));

        // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping it earlier, aborting
        // the producer thread.
        drop(client);

        bitcoind.stop()?;
        Ok(())
    }

    // Only transactions that match the predicate are delivered (Consistency).
    #[tokio::test]
    #[serial]
    async fn only_matched_transactions_delivered() -> Result<(), Box<dyn std::error::Error>> {
        // Set up new bitcoind and zmq client instance.
        let (mut client, mut bitcoind) = setup()?;

        // Get a new address that we will use to send money to.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 new blocks to that same address. We use 101 so that the coins minted in the first block can be spent
        // which we will need to do for the remainder of the test.
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // Launch a new task to issue 20 transactions paying the originally created address.
        let mine_task = tokio::task::spawn_blocking(move || {
            // Submit 20 transactions.
            for _ in 0..20 {
                bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap();
            }

            // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping it earlier,
            // aborting the producer thread. This is done in the mining thread so that the subscription stream
            // terminates.
            drop(client);

            bitcoind.stop().unwrap();
        });

        // Pull all transactions off of the subscription (until it terminates) and assert that all of them pass the
        // subscription predicate: the transactions are not a coinbase transaction.
        while let Some((tx, _)) = tx_sub.next().await {
            assert!(pred(&tx))
        }

        // Wait for the mining thread to complete.
        mine_task.await?;

        Ok(())
    }

    // All transactions that match the predicate are delivered (Completeness)
    #[tokio::test]
    #[serial]
    async fn all_matched_transactions_delivered() -> Result<(), Box<dyn std::error::Error>> {
        // Set up new bitcoind and zmq client instance.
        let (mut client, mut bitcoind) = setup()?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 blocks so that the coins in the first block are spendable.
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // Launch a task to issue 20 new transactions paying to the originally created address.
        let mine_task = tokio::task::spawn_blocking(move || {
            // Submit 20 transactions.
            for _ in 0..20 {
                bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap();
            }

            // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping it earlier,
            // aborting the producer thread. This is done in the mining thread so that the subscription stream
            // terminates.
            drop(client);

            bitcoind.stop().unwrap();
        });

        // Count all of the transactions that come over the subscription, waiting for the subscription to terminate.
        let mut n_tx = 0;
        while tx_sub.next().await.is_some() {
            n_tx += 1;
        }

        // Wait for the mining task to complete.
        mine_task.await?;

        // Assert that we received all 20 transactions over with a Mempool and Mined status for each.
        assert_eq!(n_tx, 20);

        Ok(())
    }

    // Exactly one Mined status is delivered per (transaction, block) pair (Uniqueness)
    #[tokio::test]
    #[serial]
    async fn exactly_one_mined_status_per_block() -> Result<(), Box<dyn std::error::Error>> {
        // Set up new bitcoind and zmq client instance.
        let (mut client, mut bitcoind) = setup()?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 blocks so that the coins in the first block are spendable.
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // The following is a complicated list of steps wherein we will mine a transaction, invalidate its block and
        // then mine that same transaction into a new block. We should get two Mined statuses for that transaction, one
        // corresponding to each time it was included in a block.
        //
        // We begin with grabbing the txid for the transaction we are interested in.
        let txid = bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap().txid()?;

        // Pull a transaction off of the subscription and assert that it is the Mempool event for our transaction in
        // question.
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Mempool);

        // Mine a block, and assert we get a Mined event for our transaction.
        let blockhash = bitcoind.client.generate_to_address(1, &new_address).unwrap().into_model().unwrap().0.remove(0);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Mined);

        // Now we invalidate the block we just mined, simulating a reorg. We should now get an Unknown event for that
        // transaction as it is evicted from the landscape.
        bitcoind.client.call::<()>("invalidateblock", &[serde_json::Value::String(blockhash.to_string())]).unwrap();
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Unknown);

        // Without intervention we should get a new Mempool event for our transaction as it is returned to the mempool.
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Mempool);

        // Now we add a new transaction to the mempool to ensure that a new block will not exactly match the one we
        // just invalidated.
        let txid2 = bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap().txid()?;
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid2);
        assert_eq!(observed.1, TxStatus::Mempool);

        // Mine a new block. This should include both our original transaction and the second one we created to sidestep
        // blockhash collision.
        bitcoind.client.generate_to_address(1, &new_address).unwrap().into_model().unwrap().0.remove(0);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.1, TxStatus::Mined);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.1, TxStatus::Mined);

        // Explicitly drop the client here to prevent rustc from "optimizing" the code and dropping it earlier, aborting
        // the producer thread.
        drop(client);

        // Assert that the stream has ended following the dropping of our zmq client.
        assert!(tx_sub.next().await.is_none());

        bitcoind.stop().unwrap();
        Ok(())
    }

    // Assuming there are no reorgs, Mined transactions are eventually buried (Eventual Finality)
    #[tokio::test]
    #[serial]
    async fn mined_txs_eventually_buried() -> Result<(), Box<dyn std::error::Error>> {
        // Set up new bitcoind and zmq client instance.
        let (mut client, mut bitcoind) = setup()?;

        // Create a new address that will serve as the recipient of new transactions.
        let new_address = bitcoind.client.new_address()?;

        // Mine 101 blocks so that the coins in the first block are spendable.
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // Subscribe to all non-coinbase transactions.
        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // Send a non-coinbase transaction, remembering its txid.
        let txid = bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap().txid()?;

        // Kick off a mining task that will mine a new block every 100ms until we tell it to stop.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let stop_thread = stop.clone();
        let mine_task = tokio::task::spawn_blocking(move || {
            while stop_thread.load(std::sync::atomic::Ordering::SeqCst) {
                bitcoind.client.generate_to_address(1, &new_address).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            drop(client);
            bitcoind.stop().unwrap();
        });

        // Continuously pull events off of the stream, checking for a Buried event for our transaction.
        loop {
            if let Poll::Ready(Some((tx, status))) = futures::poll!(tx_sub.next()) {
                // Once we receive a Buried event for our transaction we can abort the stream polling and stop the
                // mining task.
                if tx.compute_txid() == txid && status == TxStatus::Buried {
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
}

#[cfg(test)]
mod prop_tests {
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::Arc;

    use bitcoin::block;
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::transaction;
    use bitcoin::absolute::{Height, LockTime};
    use bitcoin::{Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use prop::array::uniform32;
    use proptest::prelude::*;
    use bitcoincore_zmq::SequenceMessage;

    use crate::{BtcZmqSM, TxPredicate, TxStatus};

    // Create a DebuggablePredicate type so we can generate dynamic predicates for the tests in this module.
    struct DebuggablePredicate {
        pred: TxPredicate,
        description: String,
    }
    impl std::fmt::Debug for DebuggablePredicate {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.description)
        }
    }

    // Generate an amount between 1sat and 21MBTC.
    prop_compose! {
        fn arb_amount()(sats in 1..2100000000000000u64) -> Amount {
            Amount::from_sat(sats)
        }
    }

    // Generate a random 32 byte hash as a Txid.
    prop_compose! {
        fn arb_txid()(bs in uniform32(any::<u8>())) -> Txid {
            Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&bs))
        }
    }

    // Generate a random OutPoint reference.
    prop_compose! {
        fn arb_outpoint()(txid in arb_txid(), vout in 0..100u32) -> OutPoint {
            OutPoint { txid, vout }
        }
    }

    // Generate a fully defined TxIn.
    prop_compose! {
        fn arb_input()(
            previous_output in arb_outpoint(),
            script_sig in uniform32(any::<u8>()).prop_map(|b| ScriptBuf::from_bytes(b.to_vec())),
            sequence in any::<u32>().prop_map(Sequence::from_consensus),
        ) -> TxIn {
            TxIn {
                previous_output,
                script_sig,
                sequence,
                witness: Witness::new(),
            }
        }
    }

    // Generate a fully defined TxOut.
    prop_compose! {
        fn arb_output()(
            value in arb_amount(),
            script_pubkey in uniform32(any::<u8>()).prop_map(|b| ScriptBuf::from_bytes(b.to_vec()))
        ) -> TxOut {
            TxOut {
                value,
                script_pubkey,
            }
        }
    }

    // Generate a random Transaction. It is not guaranteed to be consensus valid.
    prop_compose! {
        fn arb_transaction()(
            max_num_ins in 2..100u32,
            max_num_outs in 2..100u32
        )(
            ins in prop::collection::vec(arb_input(), (1, max_num_ins as usize)),
            outs in prop::collection::vec(arb_output(), (1, max_num_outs as usize))
        ) -> Transaction {
            Transaction {
                version: transaction::Version::TWO,
                lock_time: LockTime::Blocks(Height::ZERO),
                input: ins,
                output: outs,
            }
        }
    }

    // Generate a block that contains 32 random transactions. The argument defines the blockhash of the block this block
    // builds on top of.
    prop_compose! {
        fn arb_block(prev_blockhash: BlockHash)(txdata in uniform32(arb_transaction()), time in any::<u32>()) -> Block {
            let header = block::Header {
                version: block::Version::TWO,
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time,
                bits: CompactTarget::from_consensus(u32::MAX),
                nonce: 0,
            };

            let mut blk = Block {
                header,
                txdata: txdata.to_vec(),
            };

            blk.header.merkle_root = blk.compute_merkle_root().unwrap();
            blk
        }
    }

    // Generate a chain of size "length" that is anchored to "prev_blockhash".
    fn arb_chain(prev_blockhash: BlockHash, length: usize) -> BoxedStrategy<VecDeque<Block>> {
        if length == 0 {
            return Just(VecDeque::new()).boxed();
        }

        if length == 1 {
            return arb_block(prev_blockhash).prop_map(|b| VecDeque::from([b])).boxed();
        }

        let tail = arb_chain(prev_blockhash, length - 1);
        return tail.prop_flat_map(move |t| {
            let prev = t.front().unwrap().block_hash();
            arb_block(prev).prop_map(move |b| {
                let mut v = t.clone();
                v.push_front(b);
                v
            })
        }).boxed()
    }

    // Generate a random predicate that will shrink towards including all transactions.
    prop_compose! {
        fn arb_predicate()(modsize in 1..255u8) -> DebuggablePredicate {
            let pred = move |tx: &Transaction| tx.compute_txid().to_raw_hash().to_byte_array()[31] % modsize == 0;
            DebuggablePredicate {
                pred: std::sync::Arc::new(pred),
                description: format!("txid mod {} == 0", modsize),
            }
        }
    }

    proptest! {
        // Ensure that the transactions that appear in the diffs generated by the BtcZmqSM's state transition functions
        // all match the predicate we added. (Consistency)
        #[test]
        fn only_matched_transactions_in_diffs(pred in arb_predicate(), block in arb_block(Hash::all_zeros())) {
            let mut sm = BtcZmqSM::init(6);
            sm.add_filter(pred.pred.clone());
            let diff = sm.process_block(block);
            for (tx, _) in diff.iter() {
                assert!((pred.pred)(tx))
            }
        }

        // Ensure that all of the transactions match the predicate we add to the state machine appear in the diffs
        // generated by the BtcZmqSM. (Completeness)
        #[test]
        fn all_matched_transactions_in_diffs(pred in arb_predicate(), block in arb_block(Hash::all_zeros())) {
            let mut sm = BtcZmqSM::init(6);
            sm.add_filter(pred.pred.clone());
            let diff = sm.process_block(block.clone());
            assert_eq!(diff.len(), block.txdata.iter().filter(|tx| (pred.pred)(tx)).count())
        }

        // Ensure that an unaccompanied process_tx yields an empty diff.
        //
        // This serves as an important base case to ensure the uniqueness of events
        #[test]
        fn lone_process_tx_yields_empty_diff(tx in arb_transaction()) {
            let mut sm = BtcZmqSM::init(6);
            sm.add_filter(std::sync::Arc::new(|_|true));
            let diff = sm.process_tx(tx);
            assert_eq!(diff, Vec::new());
        }

        // Ensure that the order of process_tx and a corresponding MempoolAcceptance (process_sequence) does not impact
        // the total event diff when both of these are received. (seq-tx Commutativity)
        #[test]
        fn seq_tx_commutativity(tx in arb_transaction()) {
            let txid = tx.compute_txid();
            let mempool_sequence = 0u64;

            let mut sm1 = BtcZmqSM::init(6);
            sm1.add_filter(std::sync::Arc::new(|_|true));

            let diff_tx_1 = sm1.process_tx(tx.clone());
            let diff_seq_1 = sm1.process_sequence(SequenceMessage::MempoolAcceptance{ txid, mempool_sequence });

            let diff_tx_1_set = BTreeSet::from_iter(diff_tx_1.into_iter());
            let diff_seq_1_set = BTreeSet::from_iter(diff_seq_1.into_iter());
            let diff_1 = diff_tx_1_set.union(&diff_seq_1_set).cloned().collect::<BTreeSet<(Transaction, TxStatus)>>();

            let mut sm2 = BtcZmqSM::init(6);
            sm2.add_filter(std::sync::Arc::new(|_|true));

            let diff_seq_2 = sm1.process_sequence(SequenceMessage::MempoolAcceptance{ txid, mempool_sequence });
            let diff_tx_2 = sm1.process_tx(tx);

            let diff_tx_2_set = BTreeSet::from_iter(diff_tx_2.into_iter());
            let diff_seq_2_set = BTreeSet::from_iter(diff_seq_2.into_iter());
            let diff_2 = diff_tx_2_set.union(&diff_seq_2_set).cloned().collect::<BTreeSet<(Transaction, TxStatus)>>();

            assert_eq!(diff_1, diff_2);
        }

        // Ensure that a BlockDisconnect event yields an Unknown event for every transaction in that block.
        #[test]
        fn block_disconnect_drops_all_transactions(pred in arb_predicate(), block in arb_block(Hash::all_zeros())) {
            let blockhash = block.block_hash();

            let mut sm = BtcZmqSM::init(6);
            sm.add_filter(pred.pred);
            let diff_mined = sm.process_block(block);
            assert!(diff_mined.iter().map(|(_, status)| status).all(|s| *s == TxStatus::Mined));

            let diff_dropped = sm.process_sequence(SequenceMessage::BlockDisconnect{ blockhash});
            assert!(diff_dropped.iter().map(|(_, status)| status).all(|s| *s == TxStatus::Unknown));
        }

        // Ensure that adding a full bury_depth length chain of blocks on top of a block yields a Buried event for every
        // transaction in that block.
        #[test]
        fn transactions_eventually_buried(mut chain in arb_chain(Hash::all_zeros(), 7)) {
            let mut sm = BtcZmqSM::init(6);

            let oldest = chain.pop_back().unwrap();
            let diff = sm.process_block(oldest);

            let mut diff_last = Vec::new();
            for block in chain.into_iter().rev() {
                diff_last = sm.process_block(block);
            }

            let to_be_buried = diff.into_iter().map(|(tx, _)| tx.compute_txid()).collect::<BTreeSet<Txid>>();
            let is_buried = diff_last.into_iter().filter_map(|(tx, status)| if status == TxStatus::Buried {
                Some(tx.compute_txid())
            } else {
                None
            }).collect::<BTreeSet<Txid>>();

            assert_eq!(to_be_buried, is_buried);
        }

        // Ensure that receiving both a MempoolAcceptance and tx event yields a Mempool event. (seq-tx Completeness)
        #[test]
        fn seq_and_tx_make_mempool(tx in arb_transaction()) {
            let mut sm = BtcZmqSM::init(6);

            sm.add_filter(Arc::new(|_|true));

            let diff = sm.process_sequence(SequenceMessage::MempoolAcceptance { txid: tx.compute_txid(), mempool_sequence: 0 });
            assert!(diff.is_empty());

            let diff = sm.process_tx(tx.clone());
            assert_eq!(diff, vec![(tx, TxStatus::Mempool)]);
        }

        // Ensure that removing a filter after adding it results in an identical state machine (filter Invertibility).
        #[test]
        fn filter_rm_inverts_add(pred in arb_predicate()) {
            let sm_ref = BtcZmqSM::init(6);
            let mut sm = BtcZmqSM::init(6);

            sm.add_filter(pred.pred.clone());
            sm.rm_filter(&pred.pred);

            assert_eq!(sm, sm_ref);
        }

        // Ensure that a processing of a MempoolRemoval inverts the processing of a MempoolAcceptance, even if there is
        // an interceding rawtx event. (Mempool Invertibility)
        #[test]
        fn mempool_removal_inverts_acceptance(tx in arb_transaction(), include_raw in any::<bool>()) {
            let mut sm_ref = BtcZmqSM::init(6);
            sm_ref.add_filter(Arc::new(|_|true));
            let mut sm = sm_ref.clone();

            let txid = tx.compute_txid();
            sm.process_sequence(SequenceMessage::MempoolAcceptance { txid, mempool_sequence: 0 });
            if include_raw {
                sm.process_tx(tx);
            }
            sm.process_sequence(SequenceMessage::MempoolRemoval { txid, mempool_sequence: 0 });

            assert_eq!(sm, sm_ref);
        }

        // Ensure that processing a BlockDisconnect event inverts the processing of a prior rawblock event.
        // (Block Invertibility)
        #[test]
        fn block_disconnect_inverts_block(block in arb_block(Hash::all_zeros())) {
            let mut sm_ref = BtcZmqSM::init(6);
            sm_ref.add_filter(Arc::new(|_|true));
            let mut sm = sm_ref.clone();

            let blockhash = block.block_hash();
            sm.process_block(block);
            sm.process_sequence(SequenceMessage::BlockDisconnect { blockhash });

            assert_eq!(sm, sm_ref);
        }

        // Ensure that a rawtx event sampled from a rawblock event is idempotent following the rawblock event.
        // (block-tx Idempotence)
        #[test]
        fn tx_after_block_idempotence(block in arb_block(Hash::all_zeros())) {
            let mut sm_ref = BtcZmqSM::init(6);
            sm_ref.add_filter(Arc::new(|_|true));
            sm_ref.process_block(block.clone());
            let mut sm = sm_ref.clone();

            for tx in block.txdata {
                sm.process_tx(tx);
                assert_eq!(sm, sm_ref);
            }
        }

        // Ensure that we end up with the same result irrespective of the processing order of a rawblock and its
        // accompanying rawtx events. (tx-block Commutativity)
        #[test]
        fn tx_block_commutativity(block in arb_block(Hash::all_zeros())) {
            let mut sm_base = BtcZmqSM::init(6);
            sm_base.add_filter(Arc::new(|_|true));
            let mut sm_block_first = sm_base.clone();
            let mut sm_tx_first = sm_base;

            sm_block_first.process_block(block.clone());
            for tx in block.clone().txdata {
                sm_block_first.process_tx(tx);
            }

            for tx in block.clone().txdata {
                sm_tx_first.process_tx(tx);
            }
            sm_tx_first.process_block(block);

            assert_eq!(sm_tx_first, sm_block_first);
        }
    }
}