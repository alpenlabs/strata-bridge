//! The [`TxDriver`] handle that callers drive transactions through.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
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
    cpfp::{BumpOutcome, CpfpBumper, CpfpStrategy},
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
    /// Initializes a TxDriver that publishes bare transactions. A job that asks for CPFP runs as a
    /// bare job.
    pub async fn new(zmq_client: BtcNotifyClient<Connected>, rpc_client: BitcoinClient) -> Self {
        Self::start::<NoBumper>(zmq_client, rpc_client, None).await
    }

    /// Initializes a TxDriver with CPFP fee bumping.
    ///
    /// A transaction driven with [`Self::drive_with_cpfp`] goes out bare. When the node rejects
    /// it, or when its strategy asks for a bump at the publish, `bumper` attaches a child at
    /// once. After that, `bumper` keeps the package at the target on each block and each
    /// `bump_check_interval`, deadline transactions first, until the transaction is in a block.
    /// The driver stops on an unconfirmed transaction only when a buried transaction spends one
    /// of its inputs.
    pub async fn with_cpfp<B: CpfpBumper>(
        zmq_client: BtcNotifyClient<Connected>,
        rpc_client: BitcoinClient,
        bumper: Arc<B>,
        bump_check_interval: Duration,
    ) -> Self {
        Self::start(zmq_client, rpc_client, Some((bumper, bump_check_interval))).await
    }

    async fn start<B: CpfpBumper>(
        zmq_client: BtcNotifyClient<Connected>,
        rpc_client: BitcoinClient,
        bumper: Option<(Arc<B>, Duration)>,
    ) -> Self {
        let bury_depth = zmq_client.bury_depth() as u64;
        let blocks = zmq_client.subscribe_blocks().await;
        let chain = Arc::new(NodeAccess {
            zmq_client,
            rpc_client,
        });
        Self::spawn(chain, blocks, bumper, bury_depth)
    }

    /// Starts the driver loop over `chain`. `bumper` carries the bump interval with it: a driver
    /// without a bumper has no bump to run on a tick.
    pub(super) fn spawn<B: CpfpBumper>(
        chain: Arc<dyn ChainAccess>,
        blocks: Subscription<BlockEvent>,
        bumper: Option<(Arc<B>, Duration)>,
        bury_depth: u64,
    ) -> Self {
        let (jobs, receiver) = unbounded_channel();
        let (bumper, bump_interval) = bumper.unzip();
        let tracker = Tracker::new(chain, bury_depth, bumper);
        let driver = tokio::spawn(tracker.run(receiver, blocks, bump_interval));
        Self { jobs, driver }
    }

    /// Instructs the TxDriver to drive a new transaction to confirmation without CPFP.
    ///
    /// Resolves with `Ok(())` once the transaction reaches a status accepted by `condition`. It
    /// resolves with [`DriveErr::PublishFailed`] if the initial broadcast is rejected, and with
    /// [`DriveErr::Evicted`] if the transaction later leaves the mempool and cannot be rebroadcast.
    pub async fn drive(
        &self,
        tx: Transaction,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
    ) -> Result<(), DriveErr> {
        self.drive_inner(tx, condition, None).await
    }

    /// Instructs the TxDriver to drive a new transaction to confirmation with CPFP fee bumping.
    ///
    /// Resolves with `Ok(())` once the transaction reaches a status accepted by `condition`. A
    /// bump that sends no package does not fail the call: the next block or tick retries. It
    /// resolves with an error only when the transaction is buried before `condition` holds, when
    /// a conflicting transaction is buried, or when the node rejects the transaction and the
    /// bumper reports that it cannot carry a child.
    pub async fn drive_with_cpfp(
        &self,
        tx: Transaction,
        cpfp: CpfpStrategy,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
    ) -> Result<(), DriveErr> {
        self.drive_inner(tx, condition, Some(cpfp)).await
    }

    async fn drive_inner(
        &self,
        tx: Transaction,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
        cpfp: Option<CpfpStrategy>,
    ) -> Result<(), DriveErr> {
        let (respond_on, answer) = oneshot::channel();
        let caller = Caller {
            condition: Box::new(condition),
            respond_on,
        };
        self.jobs
            .send(Job { tx, caller, cpfp })
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

/// The bumper of a driver that sends bare transactions only. It has no values, so no bump can
/// run on it.
#[derive(Debug)]
enum NoBumper {}

#[async_trait]
impl CpfpBumper for NoBumper {
    type State = ();

    async fn bump(
        &self,
        _parent: &Transaction,
        _strategy: &CpfpStrategy,
        _state: &mut (),
    ) -> BumpOutcome {
        match *self {}
    }
}

impl Drop for TxDriver {
    /// Aborts the driver task. Its sends and bumps end with it, and every caller hears
    /// [`DriveErr::DriverAborted`].
    fn drop(&mut self) {
        self.driver.abort();
    }
}
