//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
use std::collections::BTreeMap;

use algebra::{
    monoid::{self, Monoid},
    semigroup::Semigroup,
};
use bitcoin::{Transaction, Txid};
use bitcoind_async_client::{error::ClientError, Client as BitcoinClient};
use futures::{channel::oneshot, stream::SelectAll, FutureExt, StreamExt};
use strata_bridge_primitives::subscription::Subscription;
use thiserror::Error;
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedSender},
    task::JoinHandle,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, info, warn};

use self::node::{ChainAccess, NodeAccess};
use crate::{
    client::{BtcNotifyClient, Connected},
    event::{TxEvent, TxStatus},
};

/// Error type for the TxDriver.
#[derive(Debug, Error)]
pub enum DriveErr {
    /// Indicates that the TxDriver has been dropped and no more events should be expected.
    #[error("tx driver has been aborted, no more events should be expected")]
    DriverAborted,

    /// Indicates that the transaction could not be published.
    #[error("could not publish transaction: {0}")]
    PublishFailed(ClientError),

    /// The transaction reached burial before the caller's condition was true. The driver
    /// stops tracking a transaction at burial, so the condition can never become true after
    /// this point.
    #[error("transaction was buried before the wait condition was met")]
    ConditionUnmet,

    /// Indicates that the transaction was evicted from the mempool and could not be rebroadcast.
    #[error("transaction {txid} was evicted from the mempool and rebroadcast failed: {source}")]
    Evicted {
        /// The id of the evicted transaction.
        txid: Txid,

        /// The error returned by the rebroadcast attempt.
        source: ClientError,
    },
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

impl TxDriveJob {
    /// Returns the condition upon which the caller needs to be notified.
    fn condition(&self) -> &(dyn Fn(&TxStatus) -> bool + Send) {
        &self.condition
    }
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

/// Rebroadcasts an evicted transaction and fails its listeners if the rebroadcast fails.
async fn resubmit(chain: &dyn ChainAccess, tx: Transaction, active_jobs: &mut TxJobHeap) {
    let txid = tx.compute_txid();
    // A reorg evicts the transaction too, and bitcoind either re-adds it to the mempool or already
    // has it in the new chain. The client reports the latter as success.
    let Err(err) = chain.broadcast(&tx).await else {
        info!(%txid, "resubmitted transaction successfully");
        return;
    };

    // bitcoind only reports a confirmed transaction as already known while one of its outputs is
    // unspent. Once they are all spent it reports the inputs as missing instead.
    if matches!(
        chain.fetch_status(txid).await,
        Ok(TxStatus::Mined { .. } | TxStatus::Buried { .. })
    ) {
        debug!(%txid, %err, "transaction is already on chain");
        return;
    }

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2690>
    // Classify the remaining failure modes, such as a double-spent input versus a fee that does not
    // replace a conflicting transaction.
    error!(%txid, %err, "could not resubmit transaction");
    for (_, respond_on) in active_jobs.remove(&txid).into_iter().flatten() {
        let evicted = DriveErr::Evicted {
            txid,
            source: err.clone(),
        };
        if respond_on.send(Err(evicted)).is_err() {
            warn!(%txid, "could not send error response to job submitter");
        }
    }
}

/// System for driving a signed transaction to confirmation.
#[derive(Debug)]
pub struct TxDriver {
    new_jobs_sender: UnboundedSender<TxDriveJob>,
    driver: JoinHandle<()>,
}

/// Lightweight health handle for the transaction driver background worker.
#[derive(Clone, Debug)]
pub struct TxDriverHealthHandle {
    new_jobs_sender: UnboundedSender<TxDriveJob>,
}

impl TxDriverHealthHandle {
    /// Returns true while the transaction driver is still accepting jobs.
    pub fn is_accepting_jobs(&self) -> bool {
        !self.new_jobs_sender.is_closed()
    }
}

impl TxDriver {
    /// Initializes the TxDriver.
    pub async fn new(zmq_client: BtcNotifyClient<Connected>, rpc_client: BitcoinClient) -> Self {
        let new_jobs = unbounded_channel::<TxDriveJob>();
        let new_jobs_sender = new_jobs.0;
        let mut block_subscription = zmq_client.subscribe_blocks().await;
        let chain = NodeAccess {
            zmq_client,
            rpc_client,
        };

        let driver = tokio::task::spawn(async move {
            let mut new_jobs_receiver_stream = UnboundedReceiverStream::new(new_jobs.1);
            let mut active_tx_subs = SelectAll::<Subscription<TxEvent>>::new();
            let mut active_jobs = TxJobHeap::empty();
            loop {
                select! {
                    Some(job) = new_jobs_receiver_stream.next().fuse() => {
                        let txid = job.tx.compute_txid();
                        let tx_sub = chain.subscribe(&job.tx).await;

                        match chain.fetch_status(txid).await {
                            Ok(TxStatus::Unknown) | Err(_) => {}
                            Ok(tx_status) => {
                                if job.condition()(&tx_status) {
                                    debug!(%txid, %tx_status, "transaction already fulfills the supplied condition, notifying job submitter");
                                    if job.respond_on.send(Ok(())).is_err() {
                                        error!("could not send response to job submitter");
                                    }
                                } else if tx_status.is_buried() {
                                    // A buried transaction sends no further event, so the condition
                                    // can never become true.
                                    if job.respond_on.send(Err(DriveErr::ConditionUnmet)).is_err() {
                                        error!("could not send error response to job submitter");
                                    }
                                } else {
                                    // if the condition is not met, we still need to add the job
                                    // to the active jobs so that we can notify it later.
                                    // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2687>
                                    // Handle the race where the relevant event may already have
                                    // happened before the subscription is established.
                                    active_tx_subs.push(tx_sub);
                                    active_jobs = active_jobs.merge(job.into());
                                }

                                continue;
                            }
                        }

                        match chain.broadcast(&job.tx).await {
                            Ok(txid) => {
                                info!(%txid, "broadcasted transaction successfully");
                                // only add subscriptions and jobs if the transaction was
                                // broadcasted successfully
                                // NOTE: (@Rajil1213) this code is duplicated here. An alternative
                                // is to add the subscription at the top and then remove them if the submission errors
                                // but removing a subscription from a `SelectAll` is not straightforward.
                                active_tx_subs.push(tx_sub);
                                active_jobs = active_jobs.merge(job.into());
                            },
                            Err(err) => {
                                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2688>
                                // If we have not hit the mempool purge rate, CPFP using the
                                // anchor from the start and retry as a package.
                                //
                                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2689>
                                // Distinguish invalid transactions and notify the job submitter
                                // instead of treating them like fee-bumping work.
                                // For now, we just inform the caller until we add fee-bumping
                                // support.
                                error!(%txid, tx=?job.tx, %err, "could not submit transaction");
                                // send feedback to the job submitter
                                if job.respond_on.send(Err(DriveErr::PublishFailed(err))).is_err() {
                                    error!("could not send error response to job submitter");
                                }
                            }
                        }
                    }
                    Some(event) = active_tx_subs.next().fuse() => {
                        match event.status {
                            TxStatus::Unknown => {
                                // Transaction has been evicted, resubmit and see what happens
                                resubmit(&chain, event.rawtx, &mut active_jobs).await;
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
                                        } else if event.status.is_buried() {
                                            // The subscription ends at burial, so the condition
                                            // can never become true.
                                            let _ = response.send(Err(DriveErr::ConditionUnmet));
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
                        // TODO: <https://alpenlabs.atlassian.net/browse/STR-2691>
                        // Compare against deadlines and CPFP using the anchor where needed.
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
    ///
    /// Resolves with `Ok(())` once the transaction reaches a status accepted by `condition`. It
    /// resolves with [`DriveErr::PublishFailed`] if the initial broadcast is rejected, and with
    /// [`DriveErr::Evicted`] if the transaction later leaves the mempool and cannot be rebroadcast.
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

    /// Returns a cloneable health handle for observing the background worker.
    pub fn health_handle(&self) -> TxDriverHealthHandle {
        TxDriverHealthHandle {
            new_jobs_sender: self.new_jobs_sender.clone(),
        }
    }
}

impl Drop for TxDriver {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
mod e2e_tests;
mod node;
