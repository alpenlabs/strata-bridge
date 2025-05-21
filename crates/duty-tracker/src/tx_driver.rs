//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
use std::collections::BTreeMap;

use algebra::{monoid::Monoid, semigroup::Semigroup};
use bitcoin::{Transaction, Txid};
use bitcoind_async_client::{traits::Broadcaster, Client as BitcoinClient};
use btc_notify::{
    client::{BtcZmqClient, TxEvent},
    subscription::Subscription,
};
use futures::{channel::oneshot, stream::SelectAll, FutureExt, StreamExt};
use thiserror::Error;
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedSender},
    task::JoinHandle,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info};

/// Error type for the TxDriver.
#[derive(Debug, Error)]
pub enum DriveErr {
    /// Indicates that the TxDriver has been dropped and no more events should be expected.
    #[error("tx driver has been aborted, no more events should be expected")]
    DriverAborted,
}

struct TxDriveJob {
    tx: Transaction,
    respond_on: oneshot::Sender<Result<(), DriveErr>>,
}

#[allow(clippy::type_complexity)]
struct TxJobHeap(BTreeMap<Txid, (Transaction, Vec<oneshot::Sender<Result<(), DriveErr>>>)>);
impl TxJobHeap {
    #[allow(clippy::type_complexity)]
    fn remove(
        &mut self,
        txid: &Txid,
    ) -> Option<(Transaction, Vec<oneshot::Sender<Result<(), DriveErr>>>)> {
        self.0.remove(txid)
    }

    fn discharge(mut self, txid: &Txid) -> Self {
        self.remove(txid)
            .into_iter()
            .flat_map(|x| {
                info!(%txid, "transaction confirmed in block");
                x.1.into_iter()
            })
            .for_each(|chan| {
                let _ = chan.send(Ok(()));
            });
        self
    }
}
impl Semigroup for TxJobHeap {
    fn merge(self, other: Self) -> Self {
        let mut a = self.0;
        let b = other.0;
        for (k, v) in b {
            match a.get_mut(&k) {
                Some(responders) => responders.1.extend(v.1),
                None => {
                    a.insert(k, v);
                }
            }
        }
        TxJobHeap(a)
    }
}
impl Monoid for TxJobHeap {
    fn empty() -> TxJobHeap {
        TxJobHeap(BTreeMap::new())
    }
}
impl From<TxDriveJob> for TxJobHeap {
    fn from(job: TxDriveJob) -> Self {
        let mut heap = BTreeMap::new();
        heap.insert(job.tx.compute_txid(), (job.tx, vec![job.respond_on]));
        TxJobHeap(heap)
    }
}
/// System for driving a signed transaction to confirmation.
#[derive(Debug)]
pub struct TxDriver {
    new_jobs_sender: UnboundedSender<TxDriveJob>,
    driver: JoinHandle<()>,
}
impl TxDriver {
    /// Initializes the TxDriver.
    pub async fn new(zmq_client: BtcZmqClient, rpc_client: BitcoinClient) -> Self {
        let new_jobs = unbounded_channel::<TxDriveJob>();
        let new_jobs_sender = new_jobs.0;
        let mut block_subscription = zmq_client.subscribe_blocks().await;

        let driver = tokio::task::spawn(async move {
            let mut new_jobs_receiver_stream = UnboundedReceiverStream::new(new_jobs.1);
            let mut active_tx_subs = SelectAll::<Subscription<TxEvent>>::new();
            let mut active_jobs = TxJobHeap::empty();
            loop {
                select! {
                    Some(job) = new_jobs_receiver_stream.next().fuse() => {
                        let rawtx_filter = job.tx.clone();
                        let rawtx_rpc_client = job.tx.clone();
                        let txid = job.tx.compute_txid();
                        let tx_sub = zmq_client.subscribe_transactions(
                            move |tx| tx == &rawtx_filter
                        ).await;
                        active_tx_subs.push(tx_sub);
                        active_jobs = active_jobs.merge(job.into());
                        match rpc_client.send_raw_transaction(&rawtx_rpc_client).await {
                            Ok(txid) => {
                                info!(%txid, "broadcasted transaction successfully");
                            },
                            Err(err) => {
                                // TODO(proofofkeags): in this case we may have not hit the mempool
                                // purge rate and then we have to probably CPFP using anchor from
                                // the getgo and try again via submit package.
                                error!(%txid, tx=?rawtx_rpc_client, %err, "could not submit transaction");
                            }
                        }
                    }
                    Some(event) = active_tx_subs.next().fuse() => {
                        match event.status {
                            btc_notify::client::TxStatus::Unknown => {
                                // Transaction has been evicted, resubmit and see what happens
                                match rpc_client.send_raw_transaction(&event.rawtx).await {
                                    Ok(_txid) => { /* NOOP, we good fam */ }
                                    Err(_err) => {
                                        // TODO(proofofkeags): in this case we need to analyze the
                                        // reported error. There are a few scenarios that can play
                                        // out here.
                                        //
                                        // 1. It failed because one or more of the inputs is double
                                        // spent.
                                        // 2. It failed because the fee didn't exceed the purge
                                        // rate.
                                        // 3. If failed because the transaction has already
                                        // re-entered the mempool automatically upon reorg.
                                    }
                                }
                            }
                            btc_notify::client::TxStatus::Buried { .. } => {
                                // Since our responsibility ends at block inclusion we will send an
                                // answer on the response channel now. It is the API caller's
                                // responsibility for handling reorgs after inclusion.
                                let txid = event.rawtx.compute_txid();
                                active_jobs = active_jobs.discharge(&txid);
                            }
                            _ => {}
                        }
                    }
                    _block = block_subscription.next().fuse() => {
                        // TODO(proofofkeags): Compare against deadlines and CPFP using anchor.
                    }
                }
            }
        });

        TxDriver {
            new_jobs_sender,
            driver,
        }
    }

    /// Instructs the TxDriver to drive a new transaction to confirmation.
    pub async fn drive(&self, tx: Transaction) -> Result<(), DriveErr> {
        let (sender, receiver) = oneshot::channel();
        self.new_jobs_sender
            .send(TxDriveJob {
                tx,
                respond_on: sender,
            })
            .map_err(|_| DriveErr::DriverAborted)?;
        receiver
            .await
            .map_err(|_| DriveErr::DriverAborted)
            .flatten()
    }
}

impl Drop for TxDriver {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
mod e2e_tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        sync::Arc,
    };

    use bitcoind_async_client::Client as BitcoinClient;
    use btc_notify::client::{BtcZmqClient, BtcZmqConfig};
    use corepc_node::CookieValues;
    use futures::join;
    use serial_test::serial;
    use strata_bridge_common::logging::{self, LoggerConfig};
    use tracing::{debug, info};

    use super::TxDriver;

    async fn setup() -> Result<(TxDriver, corepc_node::Node), Box<dyn std::error::Error>> {
        let mut bitcoin_conf = corepc_node::Conf::default();
        bitcoin_conf.enable_zmq = true;
        // TODO(proofofkeags): do dynamic port allocation so these can be run in parallel
        bitcoin_conf.args.extend(vec![
            "-zmqpubhashblock=tcp://127.0.0.1:23882",
            "-zmqpubhashtx=tcp://127.0.0.1:23883",
            "-zmqpubrawblock=tcp://127.0.0.1:23884",
            "-zmqpubrawtx=tcp://127.0.0.1:23885",
            "-zmqpubsequence=tcp://127.0.0.1:23886",
        ]);
        let bitcoind = corepc_node::Node::from_downloaded_with_conf(&bitcoin_conf)?;
        info!("corepc_node::Node initialized");

        let cfg = BtcZmqConfig::default()
            .with_hashblock_connection_string("tcp://127.0.0.1:23882")
            .with_hashtx_connection_string("tcp://127.0.0.1:23883")
            .with_rawblock_connection_string("tcp://127.0.0.1:23884")
            .with_rawtx_connection_string("tcp://127.0.0.1:23885")
            .with_sequence_connection_string("tcp://127.0.0.1:23886");

        let zmq_client = BtcZmqClient::connect(&cfg, VecDeque::new()).await?;
        info!("BtcZmqClient initialized");

        let CookieValues { user, password } = bitcoind
            .params
            .get_cookie_values()
            .expect("can read cookie")
            .expect("can parse cookie");
        let rpc_client = BitcoinClient::new(bitcoind.rpc_url(), user, password, None, None)
            .expect("can set up rpc client");
        info!("bitcoin_async_client::Client initialized");

        let tx_driver = TxDriver::new(zmq_client, rpc_client).await;
        info!("TxDriver initialized");

        Ok((tx_driver, bitcoind))
    }

    #[tokio::test]
    #[serial]
    async fn tx_drive_idempotence() -> Result<(), Box<dyn std::error::Error>> {
        logging::init(LoggerConfig::new("tx_drive_idempotence".to_string()));

        let (driver, bitcoind) = setup().await?;

        let new_address = bitcoind.client.new_address()?;
        // Mine 101 new blocks to that same address. We use 101 so that the coins minted in the
        // first block can be spent which we will need to do for the remainder of the test.
        let _ = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        debug!("waiting for test funds to mature");
        wait_for_height(&bitcoind, 101).await?;
        debug!("test funds matured");

        debug!("creating raw transaction");
        let mut outs = BTreeMap::new();
        outs.insert(new_address.to_string(), 1.0);
        let raw = bitcoind.client.create_raw_transaction(&[], &outs)?.0;
        debug!(?raw, "created raw transaction");

        debug!("funding raw transaction");
        let funded = bitcoind.client.fund_raw_transaction(&raw)?.hex;
        debug!(%funded, "funded raw transaction");

        debug!("signing raw transaction");
        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&funded)?
            .into_model()?
            .raw_transaction;
        debug!(?signed, "signed raw transaction");

        info!("sending first copy to TxDriver");
        let fst = driver.drive(signed.clone());
        info!("sending second copy to TxDriver");
        let snd = driver.drive(signed);

        info!("starting mining task");
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
        });

        debug!("waiting for TxDriver::drive calls to complete");
        let (fst_res, snd_res) = join!(fst, snd);
        info!("TxDriver::drive calls completed");

        debug!("terminating mining task");
        stop.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(1), mine_task).await??;
        info!("mining task terminated");

        fst_res.expect("first drive succeeds");
        snd_res.expect("second drive succeeds");

        Ok(())
    }

    // This is disabled because it is merely a testing helper function to ensure tests complete in
    // a timely manner, so we don't want lack of full coverage in this function to distract from
    // overall coverage.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn wait_for_height(
        rpc_client: &corepc_node::Node,
        height: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while rpc_client.client.get_blockchain_info().unwrap().blocks != height as i64 {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            })
            .await?,
        )
    }
}
