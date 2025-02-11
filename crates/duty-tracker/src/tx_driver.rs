use std::{collections::BTreeMap, ops::Sub, sync::Arc};

use bitcoin::{Block, Transaction, Txid};
use btc_notify::{
    client::{BtcZmqClient, TxEvent},
    subscription::Subscription,
};
use futures::{
    channel::oneshot,
    stream::{select_all, SelectAll},
    FutureExt, StreamExt,
};
use strata_btcio::rpc::{traits::BroadcasterRpc, BitcoinClient};
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
    task::JoinHandle,
};
use tokio_stream::wrappers::UnboundedReceiverStream;

pub enum DriveErr {
    DriverAborted,
}

pub struct TxDriver {
    new_jobs_sender: UnboundedSender<TxDriveJob>,
    driver: JoinHandle<()>,
}
pub struct TxDriveJob {
    tx: Transaction,
    deadline: usize,
    respond_on: oneshot::Sender<Result<(), DriveErr>>,
}

impl TxDriver {
    async fn new(zmq_client: BtcZmqClient, rpc_client: BitcoinClient) -> Self {
        let new_jobs = unbounded_channel::<TxDriveJob>();
        let new_jobs_sender = new_jobs.0;
        let mut block_subscription = zmq_client.subscribe_blocks().await;

        let driver = tokio::task::spawn(async move {
            let mut new_jobs_receiver_stream = UnboundedReceiverStream::new(new_jobs.1);
            let mut active_tx_subs = SelectAll::<Subscription<TxEvent>>::new();
            let mut active_jobs = BTreeMap::new();
            loop {
                select! {
                    _block = block_subscription.next().fuse() => {
                        // TODO(proofofkeags): Compare against deadlines and CPFP using anchor.
                    }
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
                            Ok(_txid) => { /* NOOP, we good fam */ }
                            Err(_err) => {
                                // TODO(proofofkeags): in this case we may have not hit the mempool
                                // purge rate and then we have to probably CPFP using anchor from
                                // the getgo and try again via submit package.
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
                            btc_notify::client::TxStatus::Mined { blockhash } => {
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
                }
            }
        });

        TxDriver {
            new_jobs_sender,
            driver,
        }
    }

    async fn drive(&self, tx: Transaction, deadline: usize) -> Result<(), DriveErr> {
        let (sender, receiver) = oneshot::channel();
        self.new_jobs_sender
            .send(TxDriveJob {
                tx,
                deadline,
                respond_on: sender,
            })
            .map_err(|_| DriveErr::DriverAborted)?;
        receiver
            .await
            .map_err(|_| DriveErr::DriverAborted)
            .flatten()
    }
}
