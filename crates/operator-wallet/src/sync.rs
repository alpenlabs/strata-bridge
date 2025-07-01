//! Operator wallet chain data sync module
use std::{collections::BTreeSet, fmt::Debug, sync::Arc};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{self},
    BlockEvent, Emitter,
};
use bdk_wallet::{
    bitcoin::{Block, OutPoint, Transaction},
    chain::CheckPoint,
    Wallet,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tracing::debug;

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
    /// Syncs a wallet using the internal update
    pub async fn sync_wallet(
        &self,
        wallet: &mut Wallet,
        leases: &mut BTreeSet<OutPoint>,
    ) -> Result<(), SyncError> {
        let last_cp = wallet.latest_checkpoint();
        let (tx, mut rx) = unbounded_channel();

        let handle = match self {
            Backend::BitcoinCore(arc) => {
                let client = arc.clone();
                tokio::spawn(async move { sync_wallet_bitcoin_core(client, last_cp, tx).await })
            }
        };

        while let Some(update) = rx.recv().await {
            match update {
                WalletUpdate::NewBlock(ev) => {
                    let height = ev.block_height();
                    let connected_to = ev.connected_to();
                    wallet
                        .apply_block_connected_to(&ev.block, height, connected_to)
                        .expect("block to be added");
                    let spent_outpoints = ev
                        .block
                        .txdata
                        .iter()
                        .flat_map(|tx| tx.input.iter())
                        .map(|txin| txin.previous_output);
                    for outpoint in spent_outpoints {
                        leases.remove(&outpoint);
                    }
                }
                WalletUpdate::MempoolTxs(txs) => {
                    let spent_outpoints = txs
                        .iter()
                        .flat_map(|a| a.0.input.iter())
                        .map(|txin| txin.previous_output);
                    for outpoint in spent_outpoints {
                        leases.remove(&outpoint);
                    }
                    wallet.apply_unconfirmed_txs(txs);
                }
            }
        }

        handle.await.expect("thread to be fine")?;

        debug!(utxo_leases=?leases, "finished operator wallet sync");

        Ok(())
    }
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
            let start_height = last_cp.height();
            with_bitcoin_core(client, move |client| {
                let mut emitter = Emitter::new(client, last_cp, start_height);
                while let Some(ev) = emitter.next_block().unwrap() {
                    send_update.send(WalletUpdate::NewBlock(ev)).unwrap();
                }
                let mempool = emitter.mempool().unwrap();
                send_update.send(WalletUpdate::MempoolTxs(mempool)).unwrap();
                Ok(())
            })
            .await
        }
    }
    .await
    .map_err(|e| (Box::new(e) as BoxedErr).into())
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
