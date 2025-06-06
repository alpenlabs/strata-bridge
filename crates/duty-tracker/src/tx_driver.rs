//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
use std::collections::BTreeMap;

use algebra::{
    monoid::{self, Monoid},
    semigroup::Semigroup,
};
use bitcoin::{Transaction, Txid};
use bitcoind_async_client::{
    traits::{Broadcaster, Reader},
    Client as BitcoinClient,
};
use btc_notify::{
    client::{BtcZmqClient, TxEvent, TxStatus},
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
use tracing::{debug, error, info};

/// Error type for the TxDriver.
#[derive(Debug, Error)]
pub enum DriveErr {
    /// Indicates that the TxDriver has been dropped and no more events should be expected.
    #[error("tx driver has been aborted, no more events should be expected")]
    DriverAborted,
}

/// This is the minimal description of a request to drive a transaction.
struct TxDriveJob {
    /// The actual transaction to publish
    tx: Transaction,

    /// The condition upon which we will notify the drive caller
    condition: Box<dyn Fn(&TxStatus) -> bool + Send>,

    /// The channel that we should publish on when the job is done.
    respond_on: oneshot::Sender<Result<(), DriveErr>>,
}

type TxSubscriberSet = Vec<(
    Box<dyn Fn(&TxStatus) -> bool + Send>,
    oneshot::Sender<Result<(), DriveErr>>,
)>;

/// The TxJobHeap is a map from [`Txid`]s to the corresponding [`Transaction`] and a list of
/// listeners for the results.
struct TxJobHeap(BTreeMap<Txid, TxSubscriberSet>);
impl TxJobHeap {
    /// Removes all jobs associated with a given [`Transaction`] and returns the job details.
    fn remove(&mut self, txid: &Txid) -> Option<TxSubscriberSet> {
        self.0.remove(txid)
    }
}

/// The Semigroup impl for TxJobHeap merges heaps so that all listeners are notified but the
/// representation is always minimally encoded.
impl Semigroup for TxJobHeap {
    fn merge(self, other: Self) -> Self {
        let mut a = self.0;
        let b = other.0;
        for (k, v) in b {
            match a.get_mut(&k) {
                Some(responders) => responders.extend(v),
                None => {
                    a.insert(k, v);
                }
            }
        }
        TxJobHeap(a)
    }
}

/// The Monoid impl for TxJobHeap yields a heap that contains no transactions it is trying to drive.
impl Monoid for TxJobHeap {
    fn empty() -> TxJobHeap {
        TxJobHeap(BTreeMap::new())
    }
}

impl From<TxDriveJob> for TxJobHeap {
    /// Converts a TxDriveJob into a TxJobHeap with a single job in it.
    fn from(job: TxDriveJob) -> Self {
        let mut heap = BTreeMap::new();
        heap.insert(job.tx.compute_txid(), vec![(job.condition, job.respond_on)]);
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

                        if rpc_client.get_raw_transaction_verbosity_zero(&txid).await.is_ok() {
                            debug!(%txid, "duplicate TxDriver::drive request. skipping resubmission.");
                            continue;
                        }

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
                            _ => {
                                let txid = event.rawtx.compute_txid();
                                let listeners = active_jobs.remove(&txid);
                                let leftovers = monoid::concat(listeners
                                    .into_iter()
                                    .flat_map(Vec::into_iter)
                                    .filter_map(|(condition, response)| {
                                        if condition(&event.status) {
                                            let _ = response.send(Ok(()));
                                            None
                                        } else {
                                            Some(
                                                TxJobHeap(
                                                    BTreeMap::from([
                                                        (txid, vec![(condition, response)])
                                                    ])
                                                )
                                            )
                                        }
                                    }));
                                active_jobs = active_jobs.merge(leftovers);
                            }
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
    pub async fn drive(
        &self,
        tx: Transaction,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
    ) -> Result<(), DriveErr> {
        let (sender, receiver) = oneshot::channel();
        self.new_jobs_sender
            .send(TxDriveJob {
                tx,
                condition: Box::new(condition),
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

    use algebra::curry;
    use bitcoind_async_client::Client as BitcoinClient;
    use btc_notify::client::{BtcZmqClient, BtcZmqConfig, TxStatus};
    use corepc_node::CookieValues;
    use futures::join;
    use serial_test::serial;
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_test_utils::prelude::wait_for_height;
    use tracing::{debug, info};

    use super::TxDriver;

    async fn setup() -> Result<(TxDriver, corepc_node::Node), Box<dyn std::error::Error>> {
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
        let bitcoind = corepc_node::Node::from_downloaded_with_conf(&bitcoin_conf)?;
        info!("corepc_node::Node initialized");

        let cfg = BtcZmqConfig::default()
            .with_hashblock_connection_string(hash_block_socket)
            .with_hashtx_connection_string(hash_tx_socket)
            .with_rawblock_connection_string(raw_block_socket)
            .with_rawtx_connection_string(raw_tx_socket)
            .with_sequence_connection_string(sequence_socket);

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
        let fst = driver.drive(signed.clone(), TxStatus::is_buried);
        info!("sending second copy to TxDriver");
        let snd = driver.drive(signed, TxStatus::is_buried);

        info!("starting mining task");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_thread = stop.clone();
        let mine_task = tokio::task::spawn_blocking(move || {
            while !stop_thread.load(std::sync::atomic::Ordering::SeqCst) {
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
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(1), mine_task).await??;
        info!("mining task terminated");

        fst_res.expect("first drive succeeds");
        snd_res.expect("second drive succeeds");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn tx_drive_mempool() -> Result<(), Box<dyn std::error::Error>> {
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

        info!("driving to mempool");
        driver
            .drive(signed.clone(), curry::eq(TxStatus::Mempool))
            .await?;
        info!("transaction appeared in mempool");

        Ok(())
    }
}
