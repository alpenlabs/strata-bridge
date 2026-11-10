//! The [`TxDriver`] handle that callers drive transactions through.

use std::sync::Arc;

use bitcoin::Transaction;
use bitcoind_async_client::Client as BitcoinClient;
use futures::channel::oneshot;
use strata_bridge_primitives::subscription::Subscription;
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedSender},
    task::JoinHandle,
};

use super::{
    errors::DriveErr,
    node::{ChainAccess, NodeAccess},
    tracker::{Caller, Job, Tracker},
};
use crate::{
    client::{BtcNotifyClient, Connected},
    event::{BlockEvent, TxStatus},
};

/// System for driving a signed transaction to confirmation.
#[derive(Debug)]
pub struct TxDriver {
    jobs: UnboundedSender<Job>,
    pub(super) driver: JoinHandle<()>,
}

/// Lightweight health handle for the transaction driver background worker.
#[derive(Clone, Debug)]
pub struct TxDriverHealthHandle {
    jobs: UnboundedSender<Job>,
}

impl TxDriverHealthHandle {
    /// Returns true while the transaction driver is still accepting jobs.
    pub fn is_accepting_jobs(&self) -> bool {
        !self.jobs.is_closed()
    }
}

impl TxDriver {
    /// Initializes a TxDriver.
    pub async fn new(zmq_client: BtcNotifyClient<Connected>, rpc_client: BitcoinClient) -> Self {
        let blocks = zmq_client.subscribe_blocks().await;
        let chain = Arc::new(NodeAccess {
            zmq_client,
            rpc_client,
        });
        Self::spawn(chain, blocks)
    }

    /// Starts the driver loop over `chain`.
    pub(super) fn spawn(chain: Arc<dyn ChainAccess>, blocks: Subscription<BlockEvent>) -> Self {
        let (jobs, receiver) = unbounded_channel();
        let tracker = Tracker::new(chain);
        let driver = tokio::spawn(tracker.run(receiver, blocks));
        Self { jobs, driver }
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
        let (respond_on, answer) = oneshot::channel();
        let caller = Caller {
            condition: Box::new(condition),
            respond_on,
        };
        self.jobs
            .send(Job { tx, caller })
            .map_err(|_| DriveErr::DriverAborted)?;
        answer.await.map_err(|_| DriveErr::DriverAborted).flatten()
    }

    /// Returns a cloneable health handle for observing the background worker.
    pub fn health_handle(&self) -> TxDriverHealthHandle {
        TxDriverHealthHandle {
            jobs: self.jobs.clone(),
        }
    }
}

impl Drop for TxDriver {
    /// Aborts the driver task. Its sends end with it, and every caller hears
    /// [`DriveErr::DriverAborted`].
    fn drop(&mut self) {
        self.driver.abort();
    }
}
