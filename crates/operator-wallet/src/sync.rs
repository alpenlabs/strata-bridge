//! Operator wallet chain data sync module
use std::{fmt::Debug, num::NonZeroU32, sync::Arc};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{self},
    BlockEvent, Emitter,
};
use bdk_wallet::{
    bitcoin::{Block, Transaction},
    chain::CheckPoint,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::debug;

use crate::persist::{PersistedWallet, WalletStore};

/// A message sent from a sync task to the syncer
#[derive(Debug)]
pub enum WalletUpdate {
    /// A newly emitted block from [`Emitter`].
    NewBlock(BlockEvent<Block>),
    /// Transactions in the mempool along with their first seen unix timestamp
    MempoolTxs(Vec<(Transaction, u64)>),
}

/// It sends updates? What did you think it did?
pub type UpdateSender = UnboundedSender<WalletUpdate>;

/// A sync backend because the internal trait isn't object safe
#[derive(Debug)]
pub enum Backend {
    /// Synchronous bitcoin core RPC client
    BitcoinCore(Arc<bitcoincore_rpc::Client>),
}

impl Backend {
    /// Syncs a wallet using the configured backend.
    ///
    /// Pulls new blocks + mempool state and applies them to the wallet's view. Staged changes are
    /// persisted to `store` every `persist_every_blocks` blocks and once after the mempool, each
    /// as a single persist call, so a crash between two calls resumes from the last one. A failed
    /// persist returns `Err` with the changes still staged for the next attempt.
    ///
    /// Lease cleanup (removing leases whose underlying outpoints have been observed spent) is the
    /// caller's responsibility — after this call, the caller compares its lease set against
    /// the wallet's `list_unspent()` and drops any lease whose outpoint is no longer present.
    pub async fn sync_wallet<P: WalletStore>(
        &self,
        wallet: &mut PersistedWallet<P>,
        store: &mut P,
        persist_every_blocks: NonZeroU32,
    ) -> Result<(), SyncError> {
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
        while let Some(update) = rx.recv().await {
            match update {
                WalletUpdate::NewBlock(ev) => {
                    let height = ev.block_height();
                    let connected_to = ev.connected_to();
                    wallet
                        .apply_block_connected_to(&ev.block, height, connected_to)
                        .expect("block to be added");
                    applied_since_persist += 1;
                    if applied_since_persist >= persist_every_blocks.get() {
                        persist(wallet, store).await?;
                        applied_since_persist = 0;
                    }
                }
                WalletUpdate::MempoolTxs(txs) => {
                    wallet.apply_unconfirmed_txs(txs);
                }
            }
        }

        // Persist what the loop applied since the last commit before surfacing an emitter
        // failure, so a failed attempt never discards durable progress.
        persist(wallet, store).await?;

        handle.await.expect("thread to be fine")?;
        Ok(())
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
                while let Some(ev) = emitter.next_block()? {
                    // A closed channel means the receiver gave up on this attempt (e.g. a persist
                    // failure). Stop emitting instead of panicking on the dropped receiver.
                    if send_update.send(WalletUpdate::NewBlock(ev)).is_err() {
                        return Ok(());
                    }
                }
                let mempool = emitter.mempool()?;
                let _ = send_update.send(WalletUpdate::MempoolTxs(mempool));
                Ok(())
            })
            .await
        }
    }
    .await
    .map_err(|e| (Box::new(e) as BoxedErr).into())
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
