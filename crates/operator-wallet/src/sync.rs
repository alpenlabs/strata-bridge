use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use bdk_bitcoind_rpc::{
    bitcoincore_rpc::{self},
    BlockEvent, Emitter,
};
use bdk_esplora::{
    esplora_client::{self, AsyncClient},
    EsploraAsyncExt,
};
use bdk_wallet::{
    bitcoin::{Block, Transaction},
    chain::{
        spk_client::{FullScanResponse, SyncRequestBuilder, SyncResponse},
        CheckPoint,
    },
    KeychainKind, Wallet,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

macro_rules! boxed_err {
    ($name:ident) => {
        impl std::ops::Deref for $name {
            type Target = BoxedInner;

            fn deref(&self) -> &Self::Target {
                self.0.as_ref()
            }
        }

        impl From<BoxedErr> for $name {
            fn from(err: BoxedErr) -> Self {
                Self(err)
            }
        }
    };
}

pub enum WalletUpdate {
    SpkSync(SyncResponse),
    SpkScan(FullScanResponse<KeychainKind>),
    NewBlock(BlockEvent<Block>),
    MempoolTxs(Vec<(Transaction, u64)>),
}

pub type UpdateSender = UnboundedSender<WalletUpdate>;

#[derive(Debug)]
pub enum Backend {
    Esplora(EsploraClient),
    BitcoinCore(Arc<bitcoincore_rpc::Client>),
}

impl Backend {
    pub async fn sync_wallet(&self, wallet: &mut Wallet) -> Result<(), SyncError> {
        let req = wallet.start_sync_with_revealed_spks();
        let last_cp = wallet.latest_checkpoint();
        let (tx, mut rx) = unbounded_channel();

        let handle = match self {
            Backend::Esplora(esplora_client) => {
                let client = esplora_client.clone();
                tokio::spawn(async move { client.sync_wallet(req, last_cp, tx).await })
            }
            Backend::BitcoinCore(arc) => {
                let client = arc.clone();
                tokio::spawn(async move { client.sync_wallet(req, last_cp, tx).await })
            }
        };

        while let Some(update) = rx.recv().await {
            match update {
                WalletUpdate::SpkSync(update) => {
                    wallet.apply_update(update).expect("update to connect")
                }
                WalletUpdate::SpkScan(update) => {
                    wallet.apply_update(update).expect("update to connect")
                }
                WalletUpdate::NewBlock(ev) => {
                    let height = ev.block_height();
                    let connected_to = ev.connected_to();
                    wallet
                        .apply_block_connected_to(&ev.block, height, connected_to)
                        .expect("block to be added")
                }
                WalletUpdate::MempoolTxs(txs) => wallet.apply_unconfirmed_txs(txs),
            }
        }

        handle.await.expect("thread to be fine")?;

        Ok(())
    }
}

trait SyncBackend: Debug + Send + Sync {
    async fn sync_wallet(
        &self,
        req: SyncRequestBuilder<(KeychainKind, u32)>,
        last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), SyncError>;
}

type BoxedInner = dyn Debug + Send + Sync;
type BoxedErr = Box<BoxedInner>;

#[derive(Debug)]
pub struct SyncError(BoxedErr);
boxed_err!(SyncError);

#[derive(Debug)]
pub struct ScanError(BoxedErr);
boxed_err!(ScanError);

#[derive(Debug)]
pub struct BroadcastTxError(BoxedErr);
boxed_err!(BroadcastTxError);

#[derive(Debug)]
pub struct GetFeeRateError(BoxedErr);
boxed_err!(GetFeeRateError);

#[derive(Clone, Debug)]
pub struct EsploraClient(AsyncClient);

impl DerefMut for EsploraClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for EsploraClient {
    type Target = AsyncClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EsploraClient {
    pub fn new(esplora_url: &str) -> Result<Self, esplora_client::Error> {
        Ok(Self(
            esplora_client::Builder::new(esplora_url).build_async()?,
        ))
    }
}

impl SyncBackend for EsploraClient {
    async fn sync_wallet(
        &self,
        req: SyncRequestBuilder<(KeychainKind, u32)>,
        _last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), SyncError> {
        let update = self
            .sync(req.build(), 3)
            .await
            .map_err(|e| Box::new(e) as BoxedErr)?;
        send_update.send(WalletUpdate::SpkSync(update)).unwrap();
        Ok(())
    }
}

impl SyncBackend for Arc<bitcoincore_rpc::Client> {
    async fn sync_wallet(
        &self,
        _req: SyncRequestBuilder<(KeychainKind, u32)>,
        last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), SyncError> {
        {
            let client = self.clone();
            async move {
                let start_height = match false {
                    true => 0,
                    false => last_cp.height(),
                };
                spawn_bitcoin_core(client.clone(), move |client| {
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
}

async fn spawn_bitcoin_core<T, F>(
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
