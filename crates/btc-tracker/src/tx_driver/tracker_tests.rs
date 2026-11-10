//! Tests that run the real driver loop with a fake node and a fake bumper.

use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use bitcoin::{hashes::Hash, BlockHash, CompactTarget, Transaction, TxMerkleNode};
use strata_bridge_primitives::subscription::Subscription;
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedSender},
    task::JoinHandle,
    time::{sleep, timeout},
};

use super::{driver::TxDriver, errors::DriveErr, test_utils::*};
use crate::event::{BlockEvent, BlockStatus, TxStatus};

/// A running driver and the handles that a test scripts it through.
struct Harness {
    driver: Arc<TxDriver>,
    chain: Arc<FakeChain>,
    blocks: UnboundedSender<BlockEvent>,
}

/// A harness for bare transactions.
fn bare_harness() -> Harness {
    let chain = Arc::new(FakeChain::default());
    let (blocks, block_receiver) = unbounded_channel();
    let driver = TxDriver::spawn(chain.clone(), Subscription::from_receiver(block_receiver));
    Harness {
        driver: Arc::new(driver),
        chain,
        blocks,
    }
}

impl Harness {
    /// Connects a block and waits until the driver has handled it.
    async fn connect_block(&self) {
        self.send_block(BlockStatus::Mined);
        self.settle().await;
    }

    fn send_block(&self, status: BlockStatus) {
        let event = BlockEvent {
            block: bitcoin::Block {
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::TWO,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 0,
                },
                txdata: Vec::new(),
            },
            status,
        };
        self.blocks.send(event).expect("the driver is running");
    }

    /// The driver has one task and short steps, so a few yields of real time drain it. A
    /// condition that must become true uses [`wait_until`] instead.
    async fn settle(&self) {
        sleep(Duration::from_millis(20)).await;
    }

    /// Drives `tx` with no CPFP from a spawned task, so that the test can script events during
    /// the wait.
    fn drive(
        &self,
        tx: &Transaction,
        condition: fn(&TxStatus) -> bool,
    ) -> JoinHandle<Result<(), DriveErr>> {
        let driver = self.driver.clone();
        let tx = tx.clone();
        tokio::spawn(async move { driver.drive(tx, condition).await })
    }

    /// Drives `tx` with no CPFP until it is buried.
    fn drive_bare(&self, tx: &Transaction) -> JoinHandle<Result<(), DriveErr>> {
        self.drive(tx, TxStatus::is_buried)
    }
}

async fn wait_until(condition: impl Fn() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !condition() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("the condition must come true");
}

async fn outcome_of(task: JoinHandle<Result<(), DriveErr>>) -> Result<(), DriveErr> {
    timeout(Duration::from_secs(5), task)
        .await
        .expect("the caller must hear an answer")
        .expect("the drive task must not panic")
}

mod bare_packages {
    use super::*;

    /// With ZMQ silent, the read on each block alone moves a transaction to burial.
    #[tokio::test]
    async fn a_read_ends_a_package_with_no_zmq_event() {
        let harness = bare_harness();
        let tx = parent(1);
        let txid = tx.compute_txid();
        let drive = harness.drive_bare(&tx);
        harness.settle().await;

        harness.chain.set_status(txid, mined());
        harness.connect_block().await;
        assert!(!drive.is_finished(), "a mined transaction is not buried");

        harness.chain.set_status(txid, buried());
        harness.connect_block().await;
        outcome_of(drive)
            .await
            .expect("the caller hears the burial");
    }

    /// ZMQ events drive the package: an event for a variant with another witness counts, and
    /// an eviction sends the transaction again.
    #[tokio::test]
    async fn zmq_events_drive_a_package_for_any_witness() {
        let harness = bare_harness();
        let tx = parent(1);
        let mut variant = tx.clone();
        variant.input[0].witness.push([7]);
        let drive = harness.drive_bare(&tx);
        harness.settle().await;

        harness.chain.emit(&variant, TxStatus::Unknown);
        let chain = harness.chain.clone();
        wait_until(move || chain.broadcasts() == 2).await;

        harness.chain.emit(&variant, mined());
        harness.chain.emit(&variant, buried());
        outcome_of(drive)
            .await
            .expect("the caller hears the burial");
    }

    /// A failed read of the node does not fail the job: the transaction goes to the send, and
    /// the node decides.
    #[tokio::test]
    async fn a_failed_read_falls_through_to_the_send() {
        let harness = bare_harness();
        harness.chain.rpc_down.store(true, Ordering::SeqCst);

        let drive = harness.drive_bare(&parent(1));
        harness.settle().await;

        assert_eq!(harness.chain.broadcasts(), 1, "the transaction goes out");
        assert!(
            !drive.is_finished(),
            "the job waits on the sent transaction"
        );
    }

    /// A status read that fails must not count as an eviction.
    #[tokio::test]
    async fn a_failed_read_leaves_the_package_as_it_is() {
        let harness = bare_harness();
        let tx = parent(1);
        harness.chain.set_status(tx.compute_txid(), mined());
        let _drive = harness.drive_bare(&tx);
        harness.settle().await;
        harness.chain.rpc_down.store(true, Ordering::SeqCst);

        harness.connect_block().await;

        assert_eq!(
            harness.chain.broadcasts(),
            0,
            "nothing goes out on a failed read"
        );
    }

    /// A buried transaction can never meet a condition that its status does not meet. The
    /// caller hears that at once, and the driver keeps nothing.
    #[tokio::test]
    async fn a_job_for_a_buried_transaction_that_misses_its_condition_fails_at_once() {
        let harness = bare_harness();
        let tx = parent(1);
        harness.chain.set_status(tx.compute_txid(), buried());

        let outcome = outcome_of(harness.drive(&tx, |_| false)).await;

        assert!(
            matches!(outcome, Err(DriveErr::ConditionUnmet)),
            "the condition can never hold, got {outcome:?}"
        );
    }

    /// A retry job that reads the transaction buried ends the package, and the first caller of
    /// a package that ZMQ never ended hears the result too.
    #[tokio::test]
    async fn a_job_that_reads_burial_ends_the_existing_package() {
        let harness = bare_harness();
        let tx = parent(1);
        let first = harness.drive(&tx, |_| false);
        harness.settle().await;

        harness.chain.set_status(tx.compute_txid(), buried());
        let retry = harness.drive_bare(&tx);

        outcome_of(retry).await.expect("the retry reads burial");
        let first = outcome_of(first).await;
        assert!(
            matches!(first, Err(DriveErr::ConditionUnmet)),
            "the first caller's condition can never hold, got {first:?}"
        );
    }

    /// A duplicate job joins the package, so it opens no second subscription.
    #[tokio::test]
    async fn a_duplicate_job_opens_no_subscription() {
        let harness = bare_harness();
        let tx = parent(1);
        let _first = harness.drive_bare(&tx);
        harness.settle().await;

        let _second = harness.drive_bare(&tx);
        harness.settle().await;

        assert_eq!(
            harness.chain.subscriptions.load(Ordering::SeqCst),
            1,
            "the package keeps its subscription"
        );
    }

    /// A job that joins a package hears its status at once, though the status does not change.
    #[tokio::test]
    async fn a_job_hears_the_status_of_the_package_it_joins() {
        let harness = bare_harness();
        let tx = parent(1);
        let _first = harness.drive_bare(&tx);
        harness.settle().await;

        let second = harness.drive(&tx, |status| *status == TxStatus::Mempool);

        outcome_of(second)
            .await
            .expect("the second caller hears the mempool");
    }

    /// A package whose ZMQ event was missed still answers its caller: the read on the next
    /// block sees the status.
    #[tokio::test]
    async fn a_package_whose_event_was_missed_answers_after_the_next_block() {
        let harness = bare_harness();
        let tx = parent(1);
        let drive = harness.drive(&tx, TxStatus::is_mined);
        harness.settle().await;

        harness.chain.set_status(tx.compute_txid(), mined());
        harness.connect_block().await;

        outcome_of(drive).await.expect("the caller hears the block");
    }

    /// A transaction that left the mempool with ZMQ silent goes back on the next block.
    #[tokio::test]
    async fn a_transaction_that_leaves_the_mempool_goes_back_on_the_next_block() {
        let harness = bare_harness();
        let tx = parent(1);
        let _drive = harness.drive_bare(&tx);
        harness.settle().await;

        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Unknown);
        harness.connect_block().await;

        assert_eq!(harness.chain.broadcasts(), 2, "the transaction goes back");
    }

    /// A transaction that the node rejects fails its caller.
    #[tokio::test]
    async fn a_rejected_send_fails_the_caller() {
        let harness = bare_harness();
        harness.chain.reject_broadcast.store(true, Ordering::SeqCst);

        let outcome = outcome_of(harness.drive_bare(&parent(1))).await;

        assert!(
            matches!(outcome, Err(DriveErr::PublishFailed(_))),
            "the caller hears the rejection, got {outcome:?}"
        );
    }

    /// A transaction that left the mempool and that the node then rejects fails its caller as
    /// evicted.
    #[tokio::test]
    async fn a_rejected_send_after_an_eviction_fails_as_evicted() {
        let harness = bare_harness();
        let tx = parent(1);
        let drive = harness.drive_bare(&tx);
        harness.settle().await;

        harness.chain.reject_broadcast.store(true, Ordering::SeqCst);
        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Unknown);
        harness.chain.emit(&tx, TxStatus::Unknown);

        let outcome = outcome_of(drive).await;
        assert!(
            matches!(outcome, Err(DriveErr::Evicted { .. })),
            "the caller hears the eviction, got {outcome:?}"
        );
    }

    /// A block that leaves the chain is read like any other, so a caller that waits for the
    /// mempool hears that the transaction went back there.
    #[tokio::test]
    async fn a_disconnected_block_is_read_like_any_other() {
        let harness = bare_harness();
        let tx = parent(1);
        harness.chain.set_status(tx.compute_txid(), mined());
        let drive = harness.drive(&tx, |status| *status == TxStatus::Mempool);
        harness.settle().await;

        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Mempool);
        harness.send_block(BlockStatus::Uncled);

        outcome_of(drive)
            .await
            .expect("the caller hears the mempool");
    }

    /// When the driver ends, its callers hear it.
    #[tokio::test]
    async fn the_callers_hear_that_the_driver_ended() {
        let harness = bare_harness();
        let drive = harness.drive_bare(&parent(1));
        harness.settle().await;

        harness.driver.driver.abort();

        let outcome = outcome_of(drive).await;
        assert!(
            matches!(outcome, Err(DriveErr::DriverAborted)),
            "the caller hears that the driver is gone, got {outcome:?}"
        );
    }
}
