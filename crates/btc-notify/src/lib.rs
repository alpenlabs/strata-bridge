use bitcoin::transaction::Transaction;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::Txid;
use bitcoincore_zmq::Message;
use bitcoincore_zmq::SequenceMessage;
use futures::Stream;
use futures::StreamExt;
use itertools::Itertools;
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
pub struct Subscription<T> {
    receiver: mpsc::Receiver<T>,
}

impl<T> Subscription<T> {
    /// Intentionally left private so as not to leak implementation details to consuming APIs.
    fn from_receiver(receiver: mpsc::Receiver<T>) -> Subscription<T> {
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
    outbox: mpsc::Sender<(Transaction, TxStatus)>,
}

pub struct BtcZmqClient {
    block_subs: Arc<Mutex<Vec<mpsc::Sender<Block>>>>,
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

        let block_subs = Arc::new(Mutex::new(Vec::<mpsc::Sender<Block>>::new()));
        let block_subs_thread = block_subs.clone();
        let tx_subs = Arc::new(Mutex::new(Vec::<TxSubscriptionDetails>::new()));
        let tx_subs_thread = tx_subs.clone();
        let state_machine_thread = state_machine.clone();
        let thread_handle = tokio::task::spawn(async move {
            loop {
                while let Some(res) = stream.next().await {
                    match res {
                        Ok(Message::HashBlock(_, _)) => { /* NOOP */ }
                        Ok(Message::HashTx(_, _)) => { /* NOOP */ }
                        Ok(Message::Block(block, _)) => {
                            let block_subs = block_subs_thread.lock().await;
                            let tx_subs = tx_subs_thread.lock().await;
                            let mut sm = state_machine_thread.lock().await;

                            // First send out the new block to all the block subs
                            // TODO: handle dropped subscriptions
                            futures::future::join_all(block_subs.iter().map(|sub| sub.send(block.clone()))).await;

                            // Now we process the block to understand what the relevant transaction diff is
                            let diff = BtcZmqSM::describe_diff(sm.process_block(block));

                            let send_jobs = diff.into_iter()
                                .cartesian_product(tx_subs.iter())
                                .filter(|((tx,_), sub)| (sub.predicate)(tx))
                                .map(|((tx,status), sub)| sub.outbox.send((tx, status)));

                            // TODO: handle dropped subscriptions
                            futures::future::join_all(send_jobs).await;
                        },
                        Ok(Message::Tx(tx, _)) => {
                            let subs = tx_subs_thread.lock().await;
                            let mut sm = state_machine_thread.lock().await;

                            let diff = BtcZmqSM::describe_diff(sm.process_tx(tx));

                            let send_jobs = diff.into_iter()
                                .cartesian_product(subs.iter())
                                .filter(|((tx, _), sub)|(sub.predicate)(tx))
                                .map(|((tx, status), sub)| sub.outbox.send((tx, status)));

                            // TODO: handle dropped subscriptions
                            futures::future::join_all(send_jobs).await;
                        },
                        Ok(Message::Sequence(seq, _)) => {
                            let subs = tx_subs_thread.lock().await;
                            let mut sm = state_machine_thread.lock().await;

                            let diff = BtcZmqSM::describe_diff(sm.process_sequence(seq));

                            let send_jobs = diff.into_iter()
                                .cartesian_product(subs.iter())
                                .filter(|((tx,_), sub)|(sub.predicate)(tx))
                                .map(|((tx,status), sub)| sub.outbox.send((tx, status)));

                            // TODO: handle dropped subscriptions
                            futures::future::join_all(send_jobs).await;
                        }
                        Err(e) => eprintln!("ERROR: {e:?}")
                    }
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

        // TODO(proofofkeags): review the correctness of this magic number and provide rationale and possible extraction
        let (send, recv) = mpsc::channel(4);

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
        // TODO(proofofkeags): review the correctness of this magic number and provide rationale and possible extraction
        let (send, recv) = mpsc::channel(10);

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
struct TxLifecycle {
    raw: Option<Transaction>,
    block: Option<BlockHash>,
    seq_received: bool,
}

/// This is the pure state machine that processes all the relevant messages. From there it will emit diffs that describe
/// the new states of transactions.
struct BtcZmqSM {
    /// This is the number of subsequent blocks that must be built on top of a given block for that block to be
    /// considered "buried": the transactions will never be reversed.
    bury_depth: usize,

    /// This is the set of predicates that are selecting for transactions, the disjunction of which we care about.
    tx_filters: Vec<TxPredicate>,

    /// This is the core data structure that holds TxLifecycles indexed by txid.
    tx_lifecycles: BTreeMap<Txid, TxLifecycle>,

    // We track the list of unburied blocks in a queue where the front is the newest block and the back is the oldest
    // "unburied" block
    unburied_blocks: VecDeque<Block>,
}

impl BtcZmqSM {
    fn init(bury_depth: usize) -> Self {
        BtcZmqSM {
            bury_depth,
            tx_filters: Vec::new(),
            tx_lifecycles: BTreeMap::new(),
            unburied_blocks: VecDeque::new(),
        }
    }

    fn add_filter(&mut self, pred: TxPredicate) {
        self.tx_filters.push(pred);
    }

    fn rm_filter(&mut self, pred: TxPredicate) {
        if let Some(idx) = self.tx_filters.iter().position(|p| Arc::ptr_eq(p, &pred)) {
            self.tx_filters.swap_remove(idx);
        }
    }

    fn describe_diff(diff: Vec<(Transaction, TxStatus)>) -> Vec<(Transaction, TxStatus)> {
        for (tx, status) in diff.iter() {
            eprintln!("{:?}: {}", status, tx.compute_txid())
        }
        diff
    }

    fn process_block(&mut self, block: Block) -> Vec<(Transaction, TxStatus)> {
        match self.unburied_blocks.front() {
            Some(tip) => {
                if block.header.prev_blockhash == tip.block_hash() {
                    self.unburied_blocks.push_front(block)
                } else {
                    unimplemented!()
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
                None => {
                    let lifecycle = TxLifecycle {
                        // TODO(proofofkeags): figure out how to make this a reference into the block we save to avoid
                        // duplicating transaction data.
                        raw: Some(matched_tx.clone()),
                        block: Some(block.block_hash()),
                        seq_received: false,
                    };
                    self.tx_lifecycles.insert(matched_tx.compute_txid(), lifecycle);
                }
                Some(lifecycle) => {
                    match (&lifecycle.raw, lifecycle.block, lifecycle.seq_received) {
                        // This should be impossible since we wouldn't have an entry for this transaction if none of
                        // these messages have been received.
                        (None, None, false) => panic!("invariant violated"),
                        // This case should be unlikely as we would expect the rawtx message to populate the first field
                        // if we have already received a seq. Nonetheless we'll handle this. Nondeterminism in the order
                        // that the different ZMQ streams are processed can also land us in this case.
                        (None, None, true) => {
                            // TODO(proofofkeags): figure out how to make this a reference into the block we save to
                            // avoid duplicating transaction data.
                            lifecycle.raw = Some(matched_tx.clone());
                            lifecycle.block = Some(block.block_hash());
                            diff.push((matched_tx.clone(), TxStatus::Mined));
                        }
                        // This should be impossible since we will always populate the full transaction data if we know
                        // the block it was in.
                        (None, Some(_), _) => panic!("invariant violated"),
                        // This case will happen if we receive a rawtx message prior to the block inclusion and sequence
                        // messages.
                        (Some(raw), None, false) => {
                            debug_assert!(raw == matched_tx, "raw transaction data mismatch when processing block");
                            lifecycle.block = Some(block.block_hash());
                            diff.push((matched_tx.clone(), TxStatus::Mined));
                        }
                        // This means that we've seen the rawtx and seq messages that got it into the mempool, and it is
                        // moving from the mempool to a block.
                        (Some(raw), None, true) => {
                            debug_assert!(raw == matched_tx, "raw transaction data mismatch when processing block");
                            lifecycle.block = Some(block.block_hash());
                            diff.push((matched_tx.clone(), TxStatus::Mined));
                        }
                        // This can happen if a transaction is reorged out of one block and into another without ever
                        // hitting the mempool.
                        (Some(raw), Some(prior_inclusion), false) => {
                            debug_assert!(raw == matched_tx, "raw transaction data mismatch when processing block");
                            debug_assert!(prior_inclusion != block.block_hash(), "block processed more than once");
                            lifecycle.block = Some(block.block_hash());
                            diff.push((matched_tx.clone(), TxStatus::Mined));
                        }
                        // This means that the transaction hit the mempool, was mined, reorged, and included in a new
                        // block.
                        (Some(raw), Some(prior_inclusion), true) => {
                            debug_assert!(raw == matched_tx, "raw transaction data mismatch when processing block");
                            debug_assert!(prior_inclusion != block.block_hash(), "block processed more than once");
                            lifecycle.block = Some(block.block_hash());
                            diff.push((matched_tx.clone(), TxStatus::Mined));
                        }
                    }
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

    fn process_tx(&mut self, tx: Transaction) -> Vec<(Transaction, TxStatus)> {
        if !self.tx_filters.iter().any(|f|f(&tx)) {
            return Vec::new();
        }

        let txid = tx.compute_txid();
        let lifecycle = self.tx_lifecycles.get_mut(&txid);
        match lifecycle {
            None => {
                let lifecycle = TxLifecycle {
                    raw: Some(tx),
                    block: None,
                    seq_received: false,
                };

                self.tx_lifecycles.insert(txid, lifecycle);

                // We intentionally DO NOT return the transaction here in the diff because we are unsure of what the
                // status is. We will either immediately get a followup block or a followup sequence which will cause us
                // to emit a new state change.
                Vec::new()
            }
            Some(lifecycle) => {
                match (&lifecycle.raw, &lifecycle.block, &lifecycle.seq_received) {
                    // This is really the only case that will cause a new event. This is because for the most part we
                    // rely on the Sequence or Block messages to "confirm" an event. This case indicates we have
                    // received a mempool acceptance event from the Sequence stream but we don't yet have the raw
                    // transaction data for it. Now that we do we can construct the full event.
                    (None, None, true) => {
                        lifecycle.raw = Some(tx.clone());
                        vec![(tx, TxStatus::Mined)]
                    }
                    // This should be impossible because we will only ever add something to the tx lifecycle map when
                    // we have some sort of associated data with it. As such one of the fields must be filled.
                    (None, None, false) => panic!("invariant violated"),
                    // We always populate the transaction data during block events so we shouldn't ever have a situation
                    // where we don't have the transaction data but we do have a blockhash for this transaction.
                    (None, Some(_), _) => panic!("invariant violated"),
                    // In all of the remaining cases, we already have the transaction data, and we have no new
                    // information about it and so we leave the diff empty.
                    (Some(_), _, _) => Vec::new(),
                }
            }
        }
    }

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
                        panic!("invariant violated: out of order block disconnect");
                    }
                }

                self.tx_lifecycles.retain(|_, v| {
                    if v.block != Some(blockhash) {
                        true
                    } else {
                        if let Some(raw) = &v.raw {
                            diff.push((raw.clone(), TxStatus::Unknown));
                        } else {
                            // TODO(proofofkeags): it occurs to me that we can simplify the lifecycle structure and make
                            // it CBC, but I'll hold off on that until the next revision.
                            panic!("invariant violated: block known when raw transaction unknown")
                        }
                        false
                    }
                });
            }
            SequenceMessage::MempoolAcceptance { txid, .. } => {
                match self.tx_lifecycles.get_mut(&txid) {
                    Some(lifecycle) => {
                        match (&lifecycle.raw, &lifecycle.block, &lifecycle.seq_received) {
                            (None, None, true) => panic!("invariant violated: duplicate mempool acceptance"),
                            (None, None, false) => panic!("invariant violated: empty tx lifecycle record"),
                            (None, Some(_), true) => panic!("invariant violated: block known without raw tx"),
                            (None, Some(_), false) => panic!("invariant violated: block known without raw tx"),
                            (Some(_), None, true) => panic!("invariant violated: duplicate mempool acceptance"),
                            (Some(raw), None, false) => { diff = vec![(raw.clone(), TxStatus::Mempool)]; },
                            (Some(_), Some(_), true) => panic!("invariant violated: duplicate mempool acceptance"),
                            (Some(_), Some(_), false) => { lifecycle.seq_received = true; }
                        }
                    }
                    None => {
                        // We insert a placeholder because we expect the rawtx event to fill in the remainder of the
                        // details.
                        //
                        // TODO(proofofkeags): since we don't have the raw tx yet we can't check for predicate matches
                        // so this will actually leak memory until we clear out these placeholders.
                        self.tx_lifecycles.insert(txid, TxLifecycle { raw: None, block: None, seq_received: true });
                    }
                }
            }
            SequenceMessage::MempoolRemoval { txid, .. } => {
                match self.tx_lifecycles.remove(&txid) {
                    Some(lifecycle) => if let Some(raw) = lifecycle.raw {
                        diff = vec![(raw, TxStatus::Unknown)];
                    }
                    None => { /* NOOP */ }
                }
            }
        }

        diff
    }
}

#[cfg(test)]
mod tests {
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
        // TODO(proofofkeags): line-by-line commentary
        let (mut client, mut bitcoind) = setup()?;
        let mut block_sub = client.subscribe_blocks().await;
        let newly_mined = bitcoind.client.generate_to_address(1, &bitcoind.client.new_address()?)?.into_model()?;
        let blk = block_sub.next().await.map(|b|b.block_hash());
        assert_eq!(newly_mined.0.first(), blk.as_ref());
        drop(client);
        bitcoind.stop()?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn basic_subscribe_transactions_functionality() -> Result<(), Box<dyn std::error::Error>> {
        // TODO(proofofkeags): line-by-line commentary
        let (mut client, mut bitcoind) = setup()?;
        let mut tx_sub = client.subscribe_transactions(|_|true).await;
        let new_address = bitcoind.client.new_address()?;
        let newly_mined = bitcoind.client.generate_to_address(1, &new_address)?.into_model()?;
        let tx = tx_sub.next().await.map(|(tx, _)|tx.compute_txid());
        let best_block = bitcoind.client.get_block(*newly_mined.0.first().unwrap())?;
        let cb = best_block.coinbase();
        assert_eq!(tx, cb.map(|cb|cb.compute_txid()));
        drop(client);
        bitcoind.stop()?;
        Ok(())
    }

    // Only transactions that match the predicate are delivered (Consistency)
    #[tokio::test]
    #[serial]
    async fn only_matched_transactions_delivered() -> Result<(), Box<dyn std::error::Error>> {
        // TODO(proofofkeags): line-by-line commentary
        let (mut client, mut bitcoind) = setup()?;
        let new_address = bitcoind.client.new_address()?;
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;

        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        let mine_task = tokio::task::spawn_blocking(move || {
            for _ in 0..20 {
                bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap();
            }
            bitcoind.client.generate_to_address(1, &new_address).unwrap();
            drop(client);
            bitcoind.stop().unwrap();
        });

        while let Some((tx, _)) = tx_sub.next().await {
            assert!(pred(&tx))
        }

        mine_task.await?;

        Ok(())
    }

    // All transactions that match the predicate are delivered (Completeness)
    #[tokio::test]
    #[serial]
    async fn all_matched_transactions_delivered() -> Result<(), Box<dyn std::error::Error>> {
        // TODO(proofofkeags): line-by-line commentary
        let (mut client, mut bitcoind) = setup()?;
        let new_address = bitcoind.client.new_address()?;
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;

        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        let mine_task = tokio::task::spawn_blocking(move || {
            for _ in 0..20 {
                bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap();
            }
            bitcoind.client.generate_to_address(1, &new_address).unwrap();
            drop(client);
            bitcoind.stop().unwrap();
        });

        let mut n_tx = 0;
        while tx_sub.next().await.is_some() {
            n_tx += 1;
        }

        mine_task.await?;
        assert_eq!(n_tx, 20);

        Ok(())
    }

    // Exactly one Mined status is delivered per (transaction, block) pair
    #[tokio::test]
    #[serial]
    async fn exactly_one_mined_status_per_block() -> Result<(), Box<dyn std::error::Error>> {
        // TODO(proofofkeags): line-by-line commentary
        let (mut client, mut bitcoind) = setup()?;
        let new_address = bitcoind.client.new_address()?;
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        // TODO(proofofkeags): tease apart the essential aspects of this linear sequence of actions.
        let txid = bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap().txid()?;
        eprintln!("candidate: {}", txid);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Mempool);
        let blockhash = bitcoind.client.generate_to_address(1, &new_address).unwrap().into_model().unwrap().0.remove(0);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Mined);
        bitcoind.client.call::<()>("invalidateblock", &[serde_json::Value::String(blockhash.to_string())]).unwrap();
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Unknown);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid);
        assert_eq!(observed.1, TxStatus::Mempool);
        let txid2 = bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap().txid()?;
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.0.compute_txid(), txid2);
        assert_eq!(observed.1, TxStatus::Mempool);
        bitcoind.client.generate_to_address(1, &new_address).unwrap().into_model().unwrap().0.remove(0);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.1, TxStatus::Mined);
        let observed = tx_sub.next().await.unwrap();
        assert_eq!(observed.1, TxStatus::Mined);
        drop(client);
        assert!(tx_sub.next().await.is_none());
        bitcoind.stop().unwrap();
        Ok(())
    }

    // Assuming there are no reorgs, Mined transactions are eventually buried
    #[tokio::test]
    #[serial]
    async fn mined_txs_eventually_buried() -> Result<(), Box<dyn std::error::Error>> {
        // TODO(proofofkeags): line-by-line commentary
        let (mut client, mut bitcoind) = setup()?;
        let new_address = bitcoind.client.new_address()?;
        let _ = bitcoind.client.generate_to_address(101, &new_address)?.into_model()?;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let pred = |tx: &Transaction| !tx.is_coinbase();
        let mut tx_sub = client.subscribe_transactions(pred).await;

        let txid = bitcoind.client.send_to_address(&new_address, bitcoin::Amount::ONE_BTC).unwrap().txid()?;

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

        loop {
            if let Poll::Ready(Some((tx, status))) = futures::poll!(tx_sub.next()) {
                if tx.compute_txid() == txid && status == TxStatus::Buried {
                    stop.store(false, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        tokio::time::timeout(std::time::Duration::from_secs(10), mine_task).await??;

        Ok(())
    }
}
