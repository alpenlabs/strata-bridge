//! Operator wallet chain data sync module
use std::{
    collections::{BTreeSet, HashSet},
    fmt::Debug,
    num::NonZeroU32,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{self, RpcApi},
    BitcoindRpcErrorExt, BlockEvent, Emitter,
};
use bdk_wallet::{
    bitcoin::{Block, Transaction, Txid},
    chain::CheckPoint,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::{debug, warn};

use crate::persist::{PersistedWallet, WalletStore};

/// A message sent from a sync task to the syncer
#[derive(Debug)]
pub enum WalletUpdate {
    /// A newly emitted block from [`Emitter`].
    NewBlock(BlockEvent<Block>),
    /// The node's mempool.
    Mempool {
        /// Every transaction in the mempool.
        txids: HashSet<Txid>,
        /// Every transaction of `txids`, along with the unix time of this sighting. The time only
        /// orders conflicting unconfirmed transactions, which one mempool never holds together, so
        /// the time of the fetch serves.
        txs: Vec<(Transaction, u64)>,
    },
}

/// The sending half that a sync task reports through.
pub type UpdateSender = UnboundedSender<WalletUpdate>;

/// A sync backend because the internal trait isn't object safe
#[derive(Debug, Clone)]
pub enum Backend {
    /// Synchronous bitcoin core RPC client
    BitcoinCore(Arc<bitcoincore_rpc::Client>),
}

impl Backend {
    /// The height of the backend's best chain.
    pub async fn height(&self) -> Result<u32, SyncError> {
        match self {
            Backend::BitcoinCore(client) => with_bitcoin_core(client.clone(), |client| {
                // Heights fit u32 long past any chain this runs against.
                client.get_block_count().map(|height| height as u32)
            })
            .await
            .map_err(|e| (Box::new(e) as BoxedErr).into()),
        }
    }

    /// Syncs a wallet using the configured backend.
    ///
    /// Pulls new blocks + mempool state and applies them to the wallet's view. Block-derived
    /// changes are persisted to `store` every `persist_every_blocks` blocks, each as a single
    /// persist call, so a crash between two calls resumes from the last one. A failed persist
    /// returns `Err` with the changes still staged for the next attempt. Mempool state is applied
    /// in memory only; only confirmed transactions are persisted.
    ///
    /// Returns the transaction ids in the node's mempool, which the caller keeps to tell a live
    /// unconfirmed transaction from one reorged out of the chain. The whole mempool is fetched and
    /// applied on every sync, so a transaction that becomes relevant to the wallet after its first
    /// sighting is still picked up.
    pub async fn sync_wallet<P: WalletStore>(
        &self,
        wallet: &mut PersistedWallet<P>,
        store: &mut P,
        persist_every_blocks: NonZeroU32,
    ) -> Result<HashSet<Txid>, SyncError> {
        let last_cp = wallet.latest_checkpoint();
        debug!(
            tip_height = last_cp.height(),
            "syncing wallet from checkpoint"
        );
        let (tx, mut rx) = unbounded_channel();

        let handle = match self {
            Backend::BitcoinCore(arc) => {
                let client = arc.clone();
                tokio::spawn(async move { sync_wallet_bitcoin_core(client, last_cp, tx).await })
            }
        };

        let mut applied_since_persist = 0u32;
        let mut mempool = HashSet::new();
        while let Some(update) = rx.recv().await {
            match update {
                WalletUpdate::NewBlock(ev) => {
                    let height = ev.block_height();
                    let connected_to = ev.connected_to();
                    wallet
                        .apply_block_connected_to(&ev.block, height, connected_to)
                        .expect("block to be added");
                    stage_anchored_txs(wallet);
                    applied_since_persist += 1;
                    if applied_since_persist >= persist_every_blocks.get() {
                        persist(wallet, store).await?;
                        applied_since_persist = 0;
                    }
                }
                WalletUpdate::Mempool { txids, txs } => {
                    // Commit the blocks, then apply the mempool and drop everything it staged: a
                    // persisted unconfirmed transaction could never be evicted, and the stream of
                    // them is unbounded.
                    persist(wallet, store).await?;
                    mempool = txids;
                    wallet.apply_unconfirmed_txs(txs);
                    let _ = wallet.take_staged();
                }
            }
        }

        // Persist what the loop applied since the last commit before surfacing an emitter
        // failure, so a failed attempt never discards durable progress.
        persist(wallet, store).await?;

        handle.await.expect("thread to be fine")?;
        Ok(mempool)
    }
}

/// Stages the transaction behind every anchor the wallet has staged.
///
/// `TxGraph::insert_tx` yields nothing for a transaction the wallet already holds, so a block
/// confirming one seen earlier in the mempool stages only its anchor. Mempool state is not
/// persisted, so without this the store would hold an anchor whose transaction is missing, and the
/// checkpoint above it would stop the block being scanned again.
fn stage_anchored_txs<P: WalletStore>(wallet: &mut PersistedWallet<P>) {
    let Some(stage) = wallet.staged() else { return };
    let staged: BTreeSet<Txid> = stage
        .tx_graph
        .txs
        .iter()
        .map(|tx| tx.compute_txid())
        .collect();
    let missing: Vec<_> = stage
        .tx_graph
        .anchors
        .iter()
        .map(|(_, txid)| *txid)
        .filter(|txid| !staged.contains(txid))
        .filter_map(|txid| wallet.tx_graph().get_tx(txid))
        .collect();
    if let Some(stage) = wallet.staged_mut() {
        stage.tx_graph.txs.extend(missing);
    }
}

/// Writes the wallet's staged changeset to `store` if there is one.
async fn persist<P: WalletStore>(
    wallet: &mut PersistedWallet<P>,
    store: &mut P,
) -> Result<(), SyncError> {
    let persisted = wallet
        .persist_async(store)
        .await
        .map_err(|e| SyncError(Box::new(e)))?;
    if persisted {
        debug!(
            tip_height = wallet.latest_checkpoint().height(),
            "persisted staged wallet state"
        );
    }
    Ok(())
}

type BoxedErrInner = dyn Debug + Send + Sync;
type BoxedErr = Box<BoxedErrInner>;

/// A generic error that happened during sync
#[derive(Debug)]
pub struct SyncError(BoxedErr);

impl std::ops::Deref for SyncError {
    type Target = BoxedErrInner;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl From<BoxedErr> for SyncError {
    fn from(err: BoxedErr) -> Self {
        Self(err)
    }
}

async fn sync_wallet_bitcoin_core(
    client: Arc<bitcoincore_rpc::Client>,
    last_cp: CheckPoint,
    send_update: UpdateSender,
) -> Result<(), SyncError> {
    {
        let client = client.clone();
        async move {
            let start_height = scan_start_height(&last_cp);
            with_bitcoin_core(client, move |client| {
                let mut emitter = Emitter::new(client, last_cp, start_height);
                if emit_blocks(&mut emitter, &send_update)? == Emitted::ReceiverGone {
                    return Ok(());
                }
                // The snapshot is good only for the tip it was read at. A block found during the
                // read takes transactions out of the snapshot, and a reorg puts them back into the
                // node's mempool, so a repeat reads it again. The mempool then applies last, and
                // no block follows it in this sync. `Emitter::mempool` cannot serve here: a second
                // call of it suppresses the transactions it already emitted, and the txid set
                // must be the whole mempool each time.
                let Some(mempool) = mempool_at_tip(
                    || fetch_mempool(client, unix_now()),
                    || emit_blocks(&mut emitter, &send_update),
                )?
                else {
                    return Ok(());
                };
                if send_update.send(mempool).is_err() {
                    warn!("sync receiver dropped, discarding the mempool snapshot");
                }
                Ok(())
            })
            .await
        }
    }
    .await
    .map_err(|e| (Box::new(e) as BoxedErr).into())
}

/// The node reads that a mempool snapshot takes.
trait MempoolSource {
    /// The id of every transaction in the mempool.
    fn mempool_txids(&self) -> Result<Vec<Txid>, bitcoincore_rpc::Error>;

    /// The transaction `txid`, or `None` when the node no longer has it. A node with `txindex`
    /// also returns a transaction that confirmed after the listing, and the block that confirmed
    /// it makes the snapshot read the mempool again.
    fn mempool_tx(&self, txid: &Txid) -> Result<Option<Transaction>, bitcoincore_rpc::Error>;
}

impl MempoolSource for bitcoincore_rpc::Client {
    fn mempool_txids(&self) -> Result<Vec<Txid>, bitcoincore_rpc::Error> {
        self.get_raw_mempool()
    }

    fn mempool_tx(&self, txid: &Txid) -> Result<Option<Transaction>, bitcoincore_rpc::Error> {
        match self.get_raw_transaction(txid, None) {
            Ok(tx) => Ok(Some(tx)),
            Err(e) if e.is_not_found_error() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// The current unix time in seconds, or `0` for a clock set before the epoch.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_secs())
}

/// Reads the mempool of `source` and fetches every transaction in it, each stamped `now`. BDK takes
/// the conflicting transaction seen last as canonical. A transaction that leaves the mempool
/// during the walk is not in the result.
fn fetch_mempool(
    source: &impl MempoolSource,
    now: u64,
) -> Result<WalletUpdate, bitcoincore_rpc::Error> {
    let mut txids = HashSet::new();
    let mut txs = Vec::new();
    for txid in source.mempool_txids()? {
        if let Some(tx) = source.mempool_tx(&txid)? {
            txs.push((tx, now));
            txids.insert(txid);
        }
    }
    Ok(WalletUpdate::Mempool { txids, txs })
}

/// Reads the mempool with `read_mempool` until `emit_blocks` finds no block after a read, and
/// returns that last read. `None` when the receiver gave up on this attempt.
fn mempool_at_tip<T, E>(
    mut read_mempool: impl FnMut() -> Result<T, E>,
    mut emit_blocks: impl FnMut() -> Result<Emitted, E>,
) -> Result<Option<T>, E> {
    loop {
        let mempool = read_mempool()?;
        match emit_blocks()? {
            Emitted::NoBlocks => return Ok(Some(mempool)),
            Emitted::Blocks => {}
            Emitted::ReceiverGone => return Ok(None),
        }
    }
}

/// What one [`emit_blocks`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Emitted {
    /// The emitter had no block left.
    NoBlocks,
    /// The emitter sent at least one block.
    Blocks,
    /// The receiver gave up on this attempt (e.g. a persist failure).
    ReceiverGone,
}

/// Sends every block that `emitter` has left. A dropped receiver stops the emission without a
/// panic.
fn emit_blocks(
    emitter: &mut Emitter<'_, bitcoincore_rpc::Client>,
    send_update: &UpdateSender,
) -> Result<Emitted, bitcoincore_rpc::Error> {
    let mut emitted = Emitted::NoBlocks;
    while let Some(ev) = emitter.next_block()? {
        let height = ev.block_height();
        if send_update.send(WalletUpdate::NewBlock(ev)).is_err() {
            warn!(height, "sync receiver dropped, stopping block emission");
            return Ok(Emitted::ReceiverGone);
        }
        emitted = Emitted::Blocks;
    }
    Ok(emitted)
}

/// Height the emitter may skip forward to when its agreement point lies below it: the wallet's
/// lowest non-genesis checkpoint, or 0 for a genesis-only chain.
///
/// Not the tip: after a reorg that leaves the node's chain shorter than the tip, a tip-based start
/// makes the emitter skip the replacement blocks once the chain regrows, leaving stale blocks in
/// the local chain.
fn scan_start_height(tip: &CheckPoint) -> u32 {
    tip.iter()
        .map(|cp| cp.height())
        .filter(|height| *height > 0)
        .last()
        .unwrap_or(0)
}

async fn with_bitcoin_core<T, F>(
    client: Arc<bitcoincore_rpc::Client>,
    func: F,
) -> Result<T, bitcoincore_rpc::Error>
where
    T: Send + 'static,
    F: FnOnce(&bitcoincore_rpc::Client) -> Result<T, bitcoincore_rpc::Error> + Send + 'static,
{
    let handle = tokio::task::spawn_blocking(move || func(&client));
    handle.await.expect("thread should be fine")
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{HashMap, VecDeque},
    };

    use bdk_wallet::bitcoin::{absolute::LockTime, transaction::Version};

    use super::*;

    /// A distinct transaction per `tag`.
    fn tx(tag: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(tag),
            input: Vec::new(),
            output: Vec::new(),
        }
    }

    /// A node whose mempool listings play back in order. The last listing repeats, and a
    /// transaction absent from `txs` reads as gone.
    #[derive(Default)]
    struct ScriptedMempool {
        listings: RefCell<VecDeque<Vec<Txid>>>,
        txs: HashMap<Txid, Transaction>,
        fetches: RefCell<Vec<Txid>>,
        fail_fetch: bool,
    }

    impl ScriptedMempool {
        fn new(listings: Vec<Vec<Txid>>, txs: &[&Transaction]) -> Self {
            Self {
                listings: RefCell::new(listings.into()),
                txs: txs
                    .iter()
                    .map(|tx| (tx.compute_txid(), (*tx).clone()))
                    .collect(),
                ..Self::default()
            }
        }
    }

    impl MempoolSource for ScriptedMempool {
        fn mempool_txids(&self) -> Result<Vec<Txid>, bitcoincore_rpc::Error> {
            let mut listings = self.listings.borrow_mut();
            let listing = if listings.len() > 1 {
                listings.pop_front()
            } else {
                listings.front().cloned()
            };
            Ok(listing.unwrap_or_default())
        }

        fn mempool_tx(&self, txid: &Txid) -> Result<Option<Transaction>, bitcoincore_rpc::Error> {
            if self.fail_fetch {
                return Err(bitcoincore_rpc::Error::ReturnedError("injected".into()));
            }
            self.fetches.borrow_mut().push(*txid);
            Ok(self.txs.get(txid).cloned())
        }
    }

    fn unpack(update: WalletUpdate) -> (HashSet<Txid>, Vec<(Transaction, u64)>) {
        match update {
            WalletUpdate::Mempool { txids, txs } => (txids, txs),
            WalletUpdate::NewBlock(_) => panic!("a mempool read yields a mempool update"),
        }
    }

    #[test]
    fn a_snapshot_holds_every_transaction_stamped_with_the_read_time() {
        let (a, b) = (tx(1), tx(2));
        let node = ScriptedMempool::new(vec![vec![a.compute_txid(), b.compute_txid()]], &[&a, &b]);
        let (txids, txs) = unpack(fetch_mempool(&node, 42).expect("read"));
        assert_eq!(
            txids,
            HashSet::from([a.compute_txid(), b.compute_txid()]),
            "every listed transaction is in the snapshot"
        );
        assert_eq!(
            txs,
            vec![(a, 42), (b, 42)],
            "each transaction carries the time of the read"
        );
    }

    #[test]
    fn a_transaction_gone_before_its_fetch_is_left_out() {
        let (a, gone) = (tx(1), tx(2));
        let node = ScriptedMempool::new(vec![vec![gone.compute_txid(), a.compute_txid()]], &[&a]);
        let (txids, txs) = unpack(fetch_mempool(&node, 0).expect("read"));
        assert_eq!(
            txids,
            HashSet::from([a.compute_txid()]),
            "the snapshot names only fetched transactions"
        );
        assert_eq!(txs.len(), 1, "the gone transaction is not applied");
    }

    #[test]
    fn a_failed_fetch_fails_the_read() {
        let a = tx(1);
        let node = ScriptedMempool {
            fail_fetch: true,
            ..ScriptedMempool::new(vec![vec![a.compute_txid()]], &[&a])
        };
        assert!(
            fetch_mempool(&node, 0).is_err(),
            "an RPC failure is not a missing transaction"
        );
    }

    /// Plays back `emissions` in order and counts the mempool reads.
    fn read_at_tip(emissions: &[Emitted]) -> (Result<Option<usize>, ()>, usize) {
        let mut reads = 0;
        let mut emissions = emissions.iter().copied();
        let result = mempool_at_tip(
            || {
                reads += 1;
                Ok(reads)
            },
            || Ok(emissions.next().expect("an emission per read")),
        );
        (result, reads)
    }

    #[test]
    fn a_quiet_tip_takes_the_first_read() {
        let (result, reads) = read_at_tip(&[Emitted::NoBlocks]);
        assert_eq!(result, Ok(Some(1)), "the first read stands");
        assert_eq!(reads, 1, "no block, so no second read");
    }

    #[test]
    fn a_block_during_the_read_reads_the_mempool_again() {
        let (result, reads) = read_at_tip(&[Emitted::Blocks, Emitted::Blocks, Emitted::NoBlocks]);
        assert_eq!(result, Ok(Some(3)), "the read after the last block stands");
        assert_eq!(reads, 3, "each block forces a new read");
    }

    #[test]
    fn a_dropped_receiver_ends_the_read_without_a_snapshot() {
        let (result, reads) = read_at_tip(&[Emitted::Blocks, Emitted::ReceiverGone]);
        assert_eq!(result, Ok(None), "nothing is left to receive a snapshot");
        assert_eq!(reads, 2, "the read stops at the dropped receiver");
    }
}
