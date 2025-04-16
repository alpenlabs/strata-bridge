//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
use std::collections::BTreeMap;

use bitcoin::Transaction;
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
            let mut active_jobs = BTreeMap::new();
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
                        active_jobs.insert(txid, job);
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
                                match active_jobs.remove(&event.rawtx.compute_txid()) {
                                    Some(job) => {
                                        let _ = job.respond_on.send(Ok(()));
                                    }
                                    None => {
                                        debug_assert!(false, "invariant violated: no job record");
                                    }
                                }
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

    /// Instructs the TxDriver to drive a new transaction to confirmation by the supplied deadline.
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
