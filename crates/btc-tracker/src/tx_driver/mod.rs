//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
use std::collections::BTreeMap;

use algebra::{
    monoid::{self, Monoid},
    semigroup::Semigroup,
};
use bitcoin::{Amount, BlockHash, OutPoint, Transaction, Txid};
use bitcoind_async_client::{
    error::ClientError,
    traits::{Broadcaster, Reader},
    types::BroadcastOptions,
    Client as BitcoinClient,
};
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
async fn resubmit(rpc_client: &BitcoinClient, tx: Transaction, active_jobs: &mut TxJobHeap) {
    let txid = tx.compute_txid();
    // A reorg evicts the transaction too, and bitcoind either re-adds it to the mempool or already
    // has it in the new chain. The client reports the latter as success.
    let Err(err) = rpc_client
        .send_raw_transaction(&tx, broadcast_options(&tx))
        .await
    else {
        info!(%txid, "resubmitted transaction successfully");
        return;
    };

    // bitcoind only reports a confirmed transaction as already known while one of its outputs is
    // unspent. Once they are all spent it reports the inputs as missing instead.
    if err.is_rpc_verify_error()
        && rpc_client
            .get_raw_transaction_verbosity_one(&txid)
            .await
            .is_ok_and(|tx_data| tx_data.confirmations.unwrap_or(0) > 0)
    {
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

/// The status of a transaction in a block of the active chain.
///
/// `confirmations` counts the containing block, and `bury_depth` counts the blocks built on top of
/// it, as the client's state machine does. A transaction with more than `bury_depth` confirmations
/// reads as buried.
const fn confirmed_status(
    confirmations: u64,
    blockhash: BlockHash,
    height: u64,
    bury_depth: u64,
) -> TxStatus {
    if confirmations > bury_depth {
        TxStatus::Buried { blockhash, height }
    } else {
        TxStatus::Mined { blockhash, height }
    }
}

/// The predicate of a transaction subscription.
///
/// The filter compares txids, not witnesses. The driver tracks whether a transaction reaches the
/// chain, not which spend path its witness takes, so a variant with another witness counts as the
/// same transaction.
fn matches_txid(tx: &Transaction) -> impl Fn(&Transaction) -> bool + Send + Sync + 'static {
    let txid = tx.compute_txid();
    let first_input = first_prevout(tx);
    // `BtcNotifyClient` runs every subscription's filter on every transaction it sees, in the
    // mempool and in each block, so this closure is on a hot path. Computing a candidate's txid
    // means a double SHA-256 over its serialization. Comparing first prevouts is a plain
    // comparison of outpoints, and it rejects nearly every other transaction before that hash
    // runs.
    //
    // The prevout check never rejects a match: the first prevout is part of the data the txid
    // commits to, so two transactions with equal txids spend the same first prevout.
    move |candidate| first_prevout(candidate) == first_input && candidate.compute_txid() == txid
}

/// The outpoint that the first input of `tx` spends.
fn first_prevout(tx: &Transaction) -> Option<OutPoint> {
    tx.input.first().map(|input| input.previous_output)
}

fn broadcast_options(tx: &Transaction) -> Option<BroadcastOptions> {
    let max_burn_amount = tx
        .output
        .iter()
        .filter(|output| output.value > Amount::ZERO && output.script_pubkey.is_op_return())
        .map(|output| output.value)
        .max()?;

    Some(BroadcastOptions {
        max_burn_amount: Some(max_burn_amount),
        ..Default::default()
    })
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
                            matches_txid(&rawtx_filter)
                        ).await;

                        if let Ok(tx_data) = rpc_client.get_raw_transaction_verbosity_one(&txid).await {
                            let num_confirmations = tx_data.confirmations.unwrap_or(0);
                            let block_hash = tx_data.block_hash;
                            let block_height = if let Some(block_hash) = block_hash {
                                // This uses `0` as the default since a block height of `0` does not
                                // satisfy any practical predicate
                                rpc_client.get_block(&block_hash).await.map(|block| block.bip34_block_height().unwrap_or(0)).unwrap_or(0)
                            } else {
                                0
                            };

                            let bury_depth = zmq_client.bury_depth() as u64;
                            let tx_status = match num_confirmations {
                                0 => TxStatus::Mempool,
                                n => confirmed_status(
                                    n,
                                    tx_data.block_hash.expect("must be present if confirmed"),
                                    block_height,
                                    bury_depth,
                                ),
                            };

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

                        let options = broadcast_options(&rawtx_rpc_client);
                        match rpc_client.send_raw_transaction(&rawtx_rpc_client, options).await {
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
                                error!(%txid, tx=?rawtx_rpc_client, %err, "could not submit transaction");
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
                                resubmit(&rpc_client, event.rawtx, &mut active_jobs).await;
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
mod tests {
    use bitcoin::{
        absolute, hashes::Hash, transaction, Amount, BlockHash, OutPoint, ScriptBuf, Transaction,
        TxIn, TxOut, Txid,
    };

    use super::{broadcast_options, confirmed_status, matches_txid};
    use crate::event::TxStatus;

    fn tx_with_outputs(output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output,
        }
    }

    /// A transaction that spends one output named by `seed`.
    fn spending(seed: u8) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
                ..TxIn::default()
            }],
            output: vec![],
        }
    }

    /// `bury_depth` counts the blocks built on top, as the client's state machine does, so a
    /// transaction is buried once it has more confirmations than that.
    #[test]
    fn confirmed_status_buries_past_the_bury_depth() {
        let blockhash = BlockHash::all_zeros();
        let mined = TxStatus::Mined {
            blockhash,
            height: 100,
        };
        let buried = TxStatus::Buried {
            blockhash,
            height: 100,
        };

        assert_eq!(
            confirmed_status(1, blockhash, 100, 6),
            mined,
            "one confirmation is mined"
        );
        assert_eq!(
            confirmed_status(6, blockhash, 100, 6),
            mined,
            "five blocks on top are short of a bury depth of six"
        );
        assert_eq!(
            confirmed_status(7, blockhash, 100, 6),
            buried,
            "six blocks on top bury the transaction"
        );
        assert_eq!(
            confirmed_status(1, blockhash, 100, 0),
            buried,
            "a bury depth of zero buries a block when it connects"
        );
    }

    #[test]
    fn the_subscription_filter_matches_another_witness_and_no_other_txid() {
        let tx = spending(1);
        let mut variant = tx.clone();
        variant.input[0].witness.push([1]);
        assert_ne!(tx, variant, "the variant carries another witness");
        let mut same_first_input = tx.clone();
        same_first_input.lock_time = absolute::LockTime::from_consensus(1);

        let filter = matches_txid(&tx);

        assert!(
            filter(&variant),
            "another witness of the transaction matches"
        );
        assert!(
            !filter(&spending(2)),
            "a transaction of another input does not match"
        );
        assert!(
            !filter(&same_first_input),
            "another txid with the same first input does not match"
        );
    }

    #[test]
    fn broadcast_options_use_largest_op_return_burn() {
        let tx = tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([1u8; 32]),
            },
            TxOut {
                value: Amount::from_sat(2_000),
                script_pubkey: ScriptBuf::new_op_return([2u8; 32]),
            },
            TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: ScriptBuf::new(),
            },
        ]);

        let options = broadcast_options(&tx).expect("OP_RETURN burn must require options");

        assert_eq!(options.max_burn_amount, Some(Amount::from_sat(2_000)));
    }
}

#[cfg(test)]
mod e2e_tests;
