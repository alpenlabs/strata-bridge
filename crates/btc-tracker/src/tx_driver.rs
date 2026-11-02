//! This module implements a system that will accept signed transactions and ensure they are posted
//! to the blockchain within a reasonable time.
//!
//! Each driven transaction has one [`ParentRecord`]. The record transitions are pure:
//! [`ParentRecord::apply`] takes one [`ParentEvent`] and returns [`ParentAction`]s, and the driver
//! loop runs those actions. All node access goes through [`ChainAccess`].
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::{Amount, BlockHash, OutPoint, Transaction, Txid};
use bitcoind_async_client::{
    error::ClientError,
    traits::{Broadcaster, Reader},
    types::BroadcastOptions,
    Client as BitcoinClient,
};
use futures::{
    channel::oneshot,
    stream::{abortable, AbortHandle, Abortable, SelectAll},
    FutureExt, StreamExt,
};
use strata_bridge_primitives::subscription::Subscription;
use thiserror::Error;
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
    task::JoinHandle,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, info, warn};

use crate::{
    client::{BtcNotifyClient, Connected},
    cpfp::{BumpOutcome, BumpState, CpfpBumper, CpfpStrategy, DeadlineClass, FirstBump},
    event::{BlockEvent, BlockStatus, TxEvent, TxStatus},
};

/// Error type for the TxDriver.
#[derive(Debug, Clone, Error)]
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

    /// A different transaction spends an input of this transaction and is buried to the bury
    /// depth. The transaction can never confirm, so the driver stopped.
    #[error("a buried transaction spends an input of the transaction")]
    ConflictBuried,
}

/// The channel that answers one caller of [`TxDriver::drive`].
type Responder = oneshot::Sender<Result<(), DriveErr>>;

/// One caller waiting for a status condition.
struct Listener {
    /// The condition upon which the caller hears `Ok`.
    condition: Box<dyn Fn(&TxStatus) -> bool + Send>,
    /// The channel that answers the caller.
    respond_on: Responder,
    /// The error of a failed bare broadcast, while only a package can take the transaction into
    /// a mempool. The next finished bump decides this caller: it joins the wait when a package
    /// went out, and it hears this error when none did.
    carried: Option<ClientError>,
}

impl Listener {
    /// A caller with no broadcast failure.
    fn new(condition: Box<dyn Fn(&TxStatus) -> bool + Send>, respond_on: Responder) -> Self {
        Self {
            condition,
            respond_on,
            carried: None,
        }
    }
}

/// This is the minimal description of a request to drive a transaction.
struct TxDriveJob {
    /// The actual transaction to publish
    tx: Transaction,

    /// The caller of this job.
    listener: Listener,

    /// Optional CPFP strategy. When present, the driver bumps the parent on each trigger until
    /// the parent confirms or the driver gives up on it.
    cpfp: Option<CpfpStrategy>,
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

/// The predicate of a transaction subscription.
///
/// The filter compares txids, because the same transaction can exist with different witnesses.
/// Every watchtower finalizes the same contest with its own signature, and a retried signing
/// round can produce a new witness. A witness-exact filter sees none of the events of a variant
/// that another party published.
///
/// The filter runs on every mempool transaction and block transaction. The first input is part
/// of the txid preimage, so it rejects nearly every other transaction with no hash.
fn matches_txid(tx: &Transaction) -> impl Fn(&Transaction) -> bool + Send + Sync + 'static {
    let txid = tx.compute_txid();
    let first_input = first_prevout(tx);
    move |candidate| first_prevout(candidate) == first_input && candidate.compute_txid() == txid
}

/// The outpoint that the first input of `tx` spends.
fn first_prevout(tx: &Transaction) -> Option<OutPoint> {
    tx.input.first().map(|input| input.previous_output)
}

/// The status of a transaction in a block of the active chain.
///
/// `confirmations` counts the containing block. A transaction with at least `bury_depth`
/// confirmations reads as buried.
const fn confirmed_status(
    confirmations: u64,
    blockhash: BlockHash,
    height: u64,
    bury_depth: u64,
) -> TxStatus {
    if confirmations >= bury_depth {
        TxStatus::Buried { blockhash, height }
    } else {
        TxStatus::Mined { blockhash, height }
    }
}

/// Node access of the driver loop.
///
/// The record logic is pure, and everything that touches the node sits behind this trait. The
/// production implementation is [`NodeAccess`]. The other implementation is the test double
/// that runs the real select loop with no node.
#[async_trait]
trait ChainAccess: Send + Sync {
    /// Opens the ZMQ subscription of `tx`.
    async fn subscribe(&self, tx: &Transaction) -> Subscription<TxEvent>;

    /// Reads the status of `txid`. A transaction that the node does not know reads as
    /// [`TxStatus::Unknown`]. An RPC failure is an error, so that a caller does not mistake a
    /// transport fault for an eviction.
    async fn fetch_status(&self, txid: Txid) -> Result<TxStatus, ClientError>;

    /// Whether a confirmed transaction spends `outpoint`.
    async fn is_spent_on_chain(&self, outpoint: OutPoint) -> Result<bool, ClientError>;

    /// Reads the height of the chain tip.
    async fn tip_height(&self) -> Result<u64, ClientError>;

    /// Sends `tx` to the mempool without a package.
    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, ClientError>;
}

/// The [`ChainAccess`] of a live node: ZMQ for subscriptions and RPC for everything else.
struct NodeAccess {
    zmq_client: BtcNotifyClient<Connected>,
    rpc_client: BitcoinClient,
}

/// The text of the client error for a `null` RPC result.
const NULL_RESULT: &str = "Empty data received";

/// Reads the status of `txid` through `getrawtransaction`. The result covers confirmed
/// transactions only when the node runs with `txindex=1`, which the bridge checks at startup.
///
/// A transaction with no confirmations reads as in the mempool. `txindex` also keeps a
/// transaction of a block that a reorg removed, with a block hash and zero confirmations, and it
/// reads the same way. Such a parent leaves its record through a ZMQ `Unknown` event or the buried
/// conflict stop, not through a reconcile. A confirmed transaction with no block hash is a
/// malformed answer, and it reads as in the mempool too, so that the driver does not stop.
async fn read_status(
    rpc_client: &BitcoinClient,
    txid: Txid,
    bury_depth: u64,
) -> Result<TxStatus, ClientError> {
    let tx_data = match rpc_client.get_raw_transaction_verbosity_one(&txid).await {
        Ok(tx_data) => tx_data,
        Err(err) if err.is_tx_not_found() => return Ok(TxStatus::Unknown),
        Err(err) => return Err(err),
    };
    match (tx_data.confirmations.unwrap_or(0), tx_data.block_hash) {
        (0, _) | (_, None) => Ok(TxStatus::Mempool),
        (confirmations, Some(blockhash)) => {
            // This uses `0` as the default since a block height of `0` does not satisfy any
            // practical predicate.
            let height = rpc_client.get_block_height(&blockhash).await.unwrap_or(0);
            Ok(confirmed_status(
                confirmations,
                blockhash,
                height,
                bury_depth,
            ))
        }
    }
}

/// Reads whether a confirmed transaction spends `outpoint`.
///
/// `gettxout` without the mempool answers `null` for a spent output, and also for an output of
/// a transaction that is not in a block. Only the first case is a spend, so a `null` counts only
/// when the transaction that creates the output is confirmed.
async fn read_spent_on_chain(
    rpc_client: &BitcoinClient,
    outpoint: OutPoint,
) -> Result<bool, ClientError> {
    match rpc_client
        .get_tx_out(&outpoint.txid, outpoint.vout, false)
        .await
    {
        Ok(_) => Ok(false),
        Err(ClientError::Other(ref msg)) if msg == NULL_RESULT => {
            match rpc_client
                .get_raw_transaction_verbosity_one(&outpoint.txid)
                .await
            {
                Ok(creator) => Ok(creator.confirmations.unwrap_or(0) > 0),
                Err(err) if err.is_tx_not_found() => Ok(false),
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }
}

#[async_trait]
impl ChainAccess for NodeAccess {
    async fn subscribe(&self, tx: &Transaction) -> Subscription<TxEvent> {
        self.zmq_client
            .subscribe_transactions(matches_txid(tx))
            .await
    }

    async fn fetch_status(&self, txid: Txid) -> Result<TxStatus, ClientError> {
        read_status(&self.rpc_client, txid, self.zmq_client.bury_depth() as u64).await
    }

    async fn is_spent_on_chain(&self, outpoint: OutPoint) -> Result<bool, ClientError> {
        read_spent_on_chain(&self.rpc_client, outpoint).await
    }

    async fn tip_height(&self) -> Result<u64, ClientError> {
        self.rpc_client.get_block_count().await
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, ClientError> {
        self.rpc_client
            .send_raw_transaction(tx, broadcast_options(tx))
            .await
    }
}

/// How far the driver has seen a transaction advance.
///
/// The absence of a record is the state after these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Not in a block. CPFP bumps run.
    Unconfirmed,
    /// In a block, not yet buried. CPFP bumps stop, because a confirmed parent needs no
    /// child. The record stays: a reorg returns the transaction to [`Self::Unconfirmed`] and
    /// the bumps must resume then. A removal at this point makes the parent unbumpable for
    /// the rest of the wait, and a floor-rate parent that no mempool accepts never confirms.
    Mined,
    /// The driver stopped bumping this parent and no caller waits on it: the last caller heard
    /// that no package went out. The record
    /// stays, because it can hold the lease of a child with an unknown fate: a release lets a
    /// concurrent duty spend an input of that child. The next job for this transaction starts a
    /// new wait on the same state. A reconcile that reads the parent in no mempool with no bump
    /// in flight ends the record, and a confirmed parent follows the chain.
    Expired,
}

/// Marks one parent as having a bump in flight, and clears the mark when it drops.
///
/// The bump task owns the guard, so the mark clears when the task ends by any route, including
/// a panic.
#[derive(Debug)]
struct BumpGuard(Arc<AtomicBool>);

impl BumpGuard {
    /// The mark that this guard holds. Two records for one txid hold different marks, so
    /// pointer identity tells a bump whether the record it started on is still the one there.
    const fn mark(&self) -> &Arc<AtomicBool> {
        &self.0
    }
}

impl Drop for BumpGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// CPFP state for one parent.
#[derive(Debug)]
struct CpfpState {
    /// Fixed for the life of the record. The txid fixes the outputs and the fee, and a call site
    /// fixes the deadline class, so a second job for the same txid has the same strategy.
    strategy: CpfpStrategy,
    /// What the bumper stored on its last attempt.
    state: BumpState,
    /// Whether a bump for this parent is in flight.
    ///
    /// One bump per parent at a time. Two concurrent bumps take a snapshot of the same
    /// handle, and the later write-back drops the lease of the live child. The mark is per
    /// parent, so a slow bump for one parent does not stop the bumps for every other parent.
    bumping: Arc<AtomicBool>,
}

impl CpfpState {
    /// A fresh state for `strategy`, with no child built yet.
    fn new(strategy: CpfpStrategy) -> Self {
        Self {
            strategy,
            state: BumpState::default(),
            bumping: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Marks a bump as in flight and returns the guard that clears the mark. Returns `None`
    /// when a bump is already running for this parent.
    fn start_bump(&self) -> Option<BumpGuard> {
        self.bumping
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| BumpGuard(Arc::clone(&self.bumping)))
    }
}

/// When the driver stops on a CPFP parent that does not confirm.
///
/// The rule reads only the chain tip, so a block that ZMQ did not deliver still counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GiveUpRules {
    /// Blocks on top of a conflicting spend before that spend counts as final.
    bury_depth: u64,
}

/// Everything the driver tracks for one transaction that it drives.
///
/// The listeners, the ZMQ subscription, and the CPFP state share one lifetime, so they share
/// one record. A single removal ends the subscription and drops the lease of the last CPFP
/// child together, and it answers each listener that is still waiting.
struct ParentRecord {
    /// The transaction. A bump uses it to rebuild the child, and a bare resubmission sends it.
    ///
    /// The record keeps the first variant that it saw. The node can hold a variant with another
    /// witness, and a package or a resubmission of this one resolves to that same txid.
    tx: Transaction,
    /// Callers that wait for a status condition.
    listeners: Vec<Listener>,
    stage: Stage,
    /// `None` when the caller asked for no CPFP, or when the bumper reported that this parent
    /// cannot carry a child.
    cpfp: Option<CpfpState>,
    /// Ends the ZMQ subscription of this transaction.
    ///
    /// [`SelectAll`] has no removal method, so each subscription enters it through
    /// [`futures::stream::abortable`]. An abort ends that stream, `SelectAll` drops it on the
    /// next poll, and the client then sweeps the closed sender and its filter.
    subscription: AbortHandle,
    /// Each input that a reconcile saw spent on chain, with the tip at the first sight.
    ///
    /// The node has no index from an outpoint to its spender. The tip is read after the spend,
    /// so the spender is in a block at or below that tip, and a tip `bury_depth` blocks higher
    /// proves the spend is buried. A disconnected block clears these entries, because the
    /// spender can move to a new block with no read that shows the output unspent. After a
    /// restart or a reorg the proof takes up to `bury_depth` blocks longer, which errs toward a
    /// later stop.
    conflicts: BTreeMap<OutPoint, u64>,
}

/// One input to [`ParentRecord::apply`].
enum ParentEvent {
    /// A status from the ZMQ subscription, or from the node when a job arrives.
    Status(TxStatus),
    /// What one reconcile read from the node.
    Reconciled {
        /// The inputs of the parent that a confirmed transaction spends. Read first, so a
        /// parent that spends them itself in a block shows up in `status`.
        spent_inputs: BTreeSet<OutPoint>,
        /// The status of the parent.
        status: TxStatus,
        /// The chain tip. Read last, so it is at or above the block of every spend.
        tip: u64,
        /// The rules that this reconcile applies.
        rules: GiveUpRules,
        /// Whether a bump for this parent was running before the status read. An expired
        /// parent takes no new bump and no job joins during a pass, so `false` here means that
        /// no bump can land a package after that read.
        bump_in_flight: bool,
    },
    /// A block left the chain, which restarts the burial of every seen conflict. This reads
    /// nothing from the node, so a failed read cannot lose it.
    Reorged,
    /// A job for this txid joined the record. A record keeps its CPFP state, which holds the
    /// lease of the live child, and a parent that lost its state stays without one: the bumper
    /// reported that every later bump fails the same way.
    JobJoined(Listener),
    /// A bump ended.
    BumpFinished {
        /// The state that the bumper left.
        state: BumpState,
        /// What the bump achieved.
        outcome: BumpOutcome,
    },
}

/// One output of [`ParentRecord::apply`].
enum ParentAction {
    /// Answers one caller.
    Answer(Responder, Result<(), DriveErr>),
    /// Removes the record. This ends the subscription and drops the lease of the last child.
    ///
    /// The parent is buried, in no mempool with no bump in flight, or spent by a buried conflict.
    /// A child can be live only in the first case, when it stays in a mempool past the burial of
    /// its parent. The wallet then sees that spend through its mempool view at the next sync.
    Remove,
    /// Puts a parent that is in no mempool back: a bump with CPFP, a bare resubmission without.
    Recover,
}

impl ParentRecord {
    /// A record at `stage` with a fresh CPFP state and no listeners.
    fn new(
        tx: Transaction,
        stage: Stage,
        cpfp: Option<CpfpStrategy>,
        subscription: AbortHandle,
    ) -> Self {
        Self {
            tx,
            listeners: Vec::new(),
            stage,
            cpfp: cpfp.map(CpfpState::new),
            subscription,
            conflicts: BTreeMap::new(),
        }
    }

    /// The pure transition function of a record. It changes the record, performs no I/O, and
    /// returns what the caller must run.
    fn apply(&mut self, event: ParentEvent) -> Vec<ParentAction> {
        match event {
            ParentEvent::Status(status) => self.apply_status(status),
            ParentEvent::Reconciled {
                spent_inputs,
                status,
                tip,
                rules,
                bump_in_flight,
            } => {
                // The txid comes first: a parent with this txid in a block under any witness
                // is not in conflict.
                match self.give_up_reason(&status, tip, spent_inputs, rules) {
                    Some(reason) => self.finish(reason),
                    // A bump in flight can still land a package, so its lease needs the record.
                    None if self.stage == Stage::Expired && status == TxStatus::Unknown => {
                        if bump_in_flight {
                            Vec::new()
                        } else {
                            vec![ParentAction::Remove]
                        }
                    }
                    None => self.apply_status(status),
                }
            }
            ParentEvent::Reorged => {
                self.conflicts.clear();
                Vec::new()
            }
            ParentEvent::JobJoined(listener) => {
                if self.stage == Stage::Expired {
                    self.stage = Stage::Unconfirmed;
                }
                if self.cpfp.is_none() {
                    if let Some(err) = listener.carried {
                        // No bump can carry this job.
                        let result = Err(DriveErr::PublishFailed(err));
                        return vec![ParentAction::Answer(listener.respond_on, result)];
                    }
                }
                self.listeners.push(listener);
                Vec::new()
            }
            ParentEvent::BumpFinished { state, outcome } => {
                if let Some(cpfp) = self.cpfp.as_mut() {
                    cpfp.state = state;
                }
                // The listeners still wait on this transaction, and the eviction path still
                // puts it back bare.
                if outcome == BumpOutcome::Unbumpable {
                    self.cpfp = None;
                }
                self.resolve_carried(outcome.reached_network())
            }
        }
    }

    /// CPFP lifecycle against confirmation depth:
    ///
    /// - Unknown: the parent is in no mempool, and in no block when the record was at `Mined`. That
    ///   is a reorg, and the bumps resume. A parent with a seen conflict stays out: the conflict
    ///   decides it. An expired parent waits for a reconcile, which also knows whether a bump is in
    ///   flight.
    /// - Mempool: wake a record at `Mined`. The cause is a reorg, or a queued event from before the
    ///   block when a reconcile set `Mined` first. The queued `Mined` event then corrects the
    ///   stage, and in that window a tick can bump a confirmed parent. An expired parent stays
    ///   expired.
    /// - Mined: stop the bumps. The record stays for the reorg case. The lease of the last child
    ///   stays too, because a parent in a block says nothing about that child: it can be in a
    ///   block, in a mempool, or dead, and the inputs of a live child must not go back to the
    ///   wallet. A woken record bumps on from that state.
    /// - Buried: final. A condition that is still false can never become true, and the caller hears
    ///   that, rather than a dropped sender that reads as an aborted driver.
    fn apply_status(&mut self, status: TxStatus) -> Vec<ParentAction> {
        match status {
            TxStatus::Unknown => {
                match self.stage {
                    Stage::Expired => return Vec::new(),
                    Stage::Mined => {
                        info!(txid = %self.tx.compute_txid(), "mined parent left its block; resuming CPFP bumps");
                        self.stage = Stage::Unconfirmed;
                    }
                    Stage::Unconfirmed => {}
                }
                if self.conflicts.is_empty() {
                    vec![ParentAction::Recover]
                } else {
                    Vec::new()
                }
            }
            TxStatus::Mempool => {
                let actions = self.notify(&status);
                self.clear_carried();
                if self.stage == Stage::Mined {
                    info!(txid = %self.tx.compute_txid(), "parent returned to the mempool; resuming CPFP bumps");
                    self.stage = Stage::Unconfirmed;
                }
                actions
            }
            TxStatus::Mined { .. } => {
                let actions = self.notify(&status);
                self.clear_carried();
                self.stage = Stage::Mined;
                self.conflicts.clear();
                actions
            }
            TxStatus::Buried { .. } => {
                let mut actions = self.notify(&status);
                actions.extend(self.finish(DriveErr::ConditionUnmet));
                actions
            }
        }
    }

    /// Answers every listener whose condition `status` satisfies, and keeps the rest.
    fn notify(&mut self, status: &TxStatus) -> Vec<ParentAction> {
        let (satisfied, waiting) = std::mem::take(&mut self.listeners)
            .into_iter()
            .partition(|listener: &Listener| (listener.condition)(status));
        self.listeners = waiting;
        satisfied
            .into_iter()
            .map(|listener: Listener| ParentAction::Answer(listener.respond_on, Ok(())))
            .collect()
    }

    /// Clears the broadcast errors. The transaction reached the network, so those errors decide
    /// no caller.
    fn clear_carried(&mut self) {
        for listener in &mut self.listeners {
            listener.carried = None;
        }
    }

    /// Decides every carried listener after a bump. With no package out, each one hears its
    /// broadcast error.
    ///
    /// The bump outcome does not show that the package stayed off the network: a timeout on the
    /// submission reports no package too. So a record with a CPFP state and no caller left goes to
    /// [`Stage::Expired`], where a reconcile ends it once the parent reads in no mempool.
    fn resolve_carried(&mut self, reached_network: bool) -> Vec<ParentAction> {
        if reached_network {
            self.clear_carried();
            return Vec::new();
        }
        let mut actions = Vec::new();
        for mut listener in std::mem::take(&mut self.listeners) {
            match listener.carried.take() {
                Some(err) => {
                    let result = Err(DriveErr::PublishFailed(err));
                    actions.push(ParentAction::Answer(listener.respond_on, result));
                }
                None => self.listeners.push(listener),
            }
        }
        if !actions.is_empty() && self.listeners.is_empty() {
            if self.cpfp.is_some() {
                self.stage = Stage::Expired;
            } else {
                actions.push(ParentAction::Remove);
            }
        }
        actions
    }

    /// Answers every listener with `reason` and removes the record.
    fn finish(&mut self, reason: DriveErr) -> Vec<ParentAction> {
        self.listeners
            .drain(..)
            .map(|listener| ParentAction::Answer(listener.respond_on, Err(reason.clone())))
            .chain([ParentAction::Remove])
            .collect()
    }

    /// Updates the give-up evidence and returns why the driver must stop on this transaction.
    ///
    /// A buried conflict stops an unconfirmed CPFP parent, because that transaction can never
    /// confirm. Nothing else stops it.
    fn give_up_reason(
        &mut self,
        status: &TxStatus,
        tip: u64,
        spent_inputs: BTreeSet<OutPoint>,
        rules: GiveUpRules,
    ) -> Option<DriveErr> {
        let unconfirmed = matches!(status, TxStatus::Mempool | TxStatus::Unknown);
        if !unconfirmed || self.stage == Stage::Expired {
            return None;
        }
        self.conflicts
            .retain(|outpoint, _| spent_inputs.contains(outpoint));
        for outpoint in spent_inputs {
            self.conflicts.entry(outpoint).or_insert(tip);
        }
        self.conflicts
            .values()
            .any(|first_seen| tip.saturating_sub(*first_seen) >= rules.bury_depth)
            .then_some(DriveErr::ConflictBuried)
    }

    /// Whether a bump can run for this parent now.
    ///
    /// A parent with a seen conflict spends a spent output, so no child of it can enter a
    /// mempool, and an attempt costs a signing round for nothing. A reorg that undoes the spend
    /// clears the conflict, and the bumps resume.
    fn is_bumpable(&self) -> bool {
        self.stage == Stage::Unconfirmed && self.cpfp.is_some() && self.conflicts.is_empty()
    }

    /// Whether a bump for this parent is running.
    fn bump_in_flight(&self) -> bool {
        self.cpfp
            .as_ref()
            .is_some_and(|cpfp| cpfp.bumping.load(Ordering::Acquire))
    }

    /// The outpoints that a reconcile must check. A record without CPFP is not reconciled: its
    /// lifecycle follows the ZMQ events alone.
    fn watched_inputs(&self) -> Vec<OutPoint> {
        if self.stage == Stage::Unconfirmed && self.cpfp.is_some() {
            self.tx.input.iter().map(|i| i.previous_output).collect()
        } else {
            Vec::new()
        }
    }
}

/// The transactions that the driver drives, keyed on txid.
///
/// `Arc<Mutex>` so a spawned bump task can take a brief lock without blocking the driver loop
/// through a wallet build, a signing round trip, and a `submitpackage` call.
type ParentMap = HashMap<Txid, ParentRecord>;
type Parents = Arc<Mutex<ParentMap>>;

/// Applies `event` to the record of `txid` and runs the actions that need only the map.
///
/// Returns whether the parent needs [`ParentAction::Recover`]. An event with no record does
/// nothing: a removal can land between an event and this call, and a removed parent has no job
/// that wants it back.
fn apply_event(map: &mut ParentMap, txid: Txid, event: ParentEvent) -> bool {
    let Some(record) = map.get_mut(&txid) else {
        return false;
    };
    let mut recover = false;
    for action in record.apply(event) {
        match action {
            ParentAction::Answer(respond_on, result) => {
                let _ = respond_on.send(result);
            }
            ParentAction::Remove => {
                if let Some(record) = map.remove(&txid) {
                    record.subscription.abort();
                }
            }
            ParentAction::Recover => recover = true,
        }
    }
    recover
}

/// The record of `txid`, when its CPFP state holds `mark`.
///
/// Two records can hold one txid over the life of a bump. A task reads and writes the CPFP state
/// only through this check, so a task that started on a removed record never touches the state of
/// a newer one.
fn marked_record<'a>(
    map: &'a ParentMap,
    txid: &Txid,
    mark: &Arc<AtomicBool>,
) -> Option<&'a ParentRecord> {
    map.get(txid).filter(|record| {
        record
            .cpfp
            .as_ref()
            .is_some_and(|cpfp| Arc::ptr_eq(&cpfp.bumping, mark))
    })
}

/// The parents that a walk bumps, in walk order: deadline parents first, then by txid.
fn batch_order(map: &ParentMap) -> Vec<Txid> {
    let mut walk: Vec<_> = map
        .iter()
        .filter(|(_, record)| record.is_bumpable())
        .filter_map(|(txid, record)| Some((record.cpfp.as_ref()?.strategy.deadline, *txid)))
        .collect();
    walk.sort_by_key(|(deadline, txid)| (*deadline != DeadlineClass::Deadline, *txid));
    walk.into_iter().map(|(_, txid)| txid).collect()
}

/// What a bump task does when no package goes out.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BumpFollowUp {
    /// Nothing. The next trigger retries.
    Wait,
    /// Put the bare parent back. The eviction path needs this: a declined bump leaves the parent
    /// in no mempool at all. Carries the transaction of the eviction event when there is one;
    /// otherwise the record's transaction goes out.
    ResubmitBare(Option<Transaction>),
}

impl BumpFollowUp {
    /// Runs the follow-up. `outcome` is `None` when no bump ran.
    ///
    /// [`BumpOutcome::ParentIsLive`] counts as a package. The parent is in a mempool or in a
    /// block, so a bare resubmission is waste.
    async fn run(self, driver: &DriverCore, parent_txid: Txid, outcome: Option<BumpOutcome>) {
        let reached_network = outcome.is_some_and(BumpOutcome::reached_network);
        if let Self::ResubmitBare(tx) = self {
            if !reached_network {
                driver.resubmit_bare(parent_txid, tx).await;
            }
        }
    }
}

/// The ZMQ subscriptions of every record.
type ActiveSubscriptions = SelectAll<Abortable<Subscription<TxEvent>>>;

/// The handles that the driver loop and its bump tasks share.
#[derive(Clone)]
struct DriverCore {
    chain: Arc<dyn ChainAccess>,
    /// `None` for a driver that publishes bare transactions only.
    bumper: Option<Arc<dyn CpfpBumper>>,
    parents: Parents,
    rules: GiveUpRules,
}

impl DriverCore {
    /// Sends `tx`, or the transaction of the record for `txid`, without a package. This is the
    /// path for a parent without CPFP, and the fallback when a bump submits no package.
    async fn resubmit_bare(&self, txid: Txid, tx: Option<Transaction>) {
        let tracked = self
            .parents
            .lock()
            .await
            .get(&txid)
            .map(|record| record.tx.clone());
        let Some(tx) = tx.or(tracked) else {
            return;
        };
        match self.chain.broadcast(&tx).await {
            Ok(txid) => {
                info!(%txid, "resubmitted transaction successfully");
            }
            Err(err) => {
                error!(%txid, %err, "could not resubmit transaction");
                // TODO: <https://alpenlabs.atlassian.net/browse/STR-2690>
                // Analyze the reported error and classify the submission failure mode: a double
                // spend of an input, a fee under the purge rate, or a transaction that a reorg
                // already returned to the mempool.
            }
        }
    }

    /// Runs one bump for `parent_txid` and writes the updated state back.
    ///
    /// Returns `None` without a bump when the record is gone, or when its stage is not
    /// `Unconfirmed`. An event settles the parent that way between the caller's look-up and
    /// this one.
    ///
    /// The state is written back **whatever the outcome**. The bumper stores the lease on the
    /// new child's funding inputs before the steps that can fail, and the write-back keeps that
    /// lease for the next attempt.
    async fn bump_parent(&self, parent_txid: Txid, mark: &Arc<AtomicBool>) -> Option<BumpOutcome> {
        // Snapshot under a brief lock. The slow bump runs without the parents mutex held.
        let snapshot = {
            let guard = self.parents.lock().await;
            marked_record(&guard, &parent_txid, mark)
                .filter(|record| record.is_bumpable())
                .and_then(|record| {
                    let cpfp = record.cpfp.as_ref()?;
                    Some((record.tx.clone(), cpfp.strategy.clone(), cpfp.state.clone()))
                })
        };
        let (parent, strategy, mut state) = snapshot?;
        let outcome = self
            .bumper
            .as_ref()?
            .bump(&parent, &strategy, &mut state)
            .await;

        // A record that has gone or holds another mark means that an event settled this parent
        // during the bump. No package of this bump can be live after a buried conflict, and a
        // reconcile keeps an expired record for a bump in flight. A package can be live after a
        // burial, which `ParentAction::Remove` states. The local state drops
        // at the end of this function, and when this bump built a child, it owns the only clone
        // of that lease.
        let mut guard = self.parents.lock().await;
        if marked_record(&guard, &parent_txid, mark).is_some() {
            apply_event(
                &mut guard,
                parent_txid,
                ParentEvent::BumpFinished { state, outcome },
            );
        }
        Some(outcome)
    }

    /// Takes the bump mark for `parent_txid` when that parent can take a bump now.
    ///
    /// The mark is taken under the records lock, so two triggers cannot both start a bump for
    /// one parent.
    async fn take_bump_mark(&self, parent_txid: Txid) -> Option<BumpGuard> {
        let guard = self.parents.lock().await;
        let record = guard.get(&parent_txid).filter(|r| r.is_bumpable())?;
        record.cpfp.as_ref().and_then(CpfpState::start_bump)
    }

    /// Runs one bump for `parent_txid` when that parent can take one, and then `follow_up`.
    ///
    /// A parent that cannot take one still runs `follow_up`, so an evicted parent goes back into
    /// the mempool when another trigger holds the mark, and so does one with no CPFP.
    async fn bump_once(&self, parent_txid: Txid, follow_up: BumpFollowUp) {
        let outcome = match self.take_bump_mark(parent_txid).await {
            Some(guard) => self.bump_parent(parent_txid, guard.mark()).await,
            None => None,
        };
        follow_up.run(self, parent_txid, outcome).await;
    }

    /// Spawns [`Self::bump_once`]. A bump can wait minutes on a signer, and the driver loop must
    /// keep delivering status events during that wait.
    fn spawn_bump(&self, parent_txid: Txid, follow_up: BumpFollowUp) {
        let driver = self.clone();
        tokio::spawn(async move {
            driver.bump_once(parent_txid, follow_up).await;
        });
    }

    /// Spawns one walk over every parent that can take a bump, deadline parents first.
    ///
    /// A walk runs its bumps one after another, so one trigger does not start a signing round
    /// for every parent at once. Walks overlap: each trigger starts a new one, and the per-parent
    /// mark skips a parent that is in flight. A slow bump therefore delays a deadline parent
    /// only until the next trigger. The first bump of a new job does not pass through a walk.
    ///
    /// `recovering` holds the parents that a reconcile found in no mempool. A walk puts them
    /// back through the bare path once their bump sends no package. A parent that leaves the walk
    /// between the reconcile and this read waits for the next trigger.
    async fn spawn_batch_bump(&self, recovering: HashSet<Txid>) {
        let walk = batch_order(&*self.parents.lock().await);
        let driver = self.clone();
        tokio::spawn(async move {
            for parent_txid in walk {
                let follow_up = if recovering.contains(&parent_txid) {
                    BumpFollowUp::ResubmitBare(None)
                } else {
                    BumpFollowUp::Wait
                };
                driver.bump_once(parent_txid, follow_up).await;
            }
        });
    }

    /// Reads every CPFP parent from the node, applies the result, and returns the parents that
    /// are in no mempool. A record without CPFP follows the ZMQ events alone.
    ///
    /// This is what ends a CPFP record when ZMQ does not: a dropped message, or an event that
    /// happened before the subscription existed. A record that cannot be read keeps its state, and
    /// the next block retries it. The pass runs in the driver loop, so no ZMQ event interleaves
    /// with a record between its read and its update, and the walk that follows sees the
    /// result. A bump task can still finish during the pass.
    ///
    /// The node serves the block before ZMQ does, so the walk after this pass does not bump a
    /// parent that the same block mined.
    async fn reconcile(&self) -> HashSet<Txid> {
        let mut recovering = HashSet::new();
        let watched: Vec<(Txid, Vec<OutPoint>)> = self
            .parents
            .lock()
            .await
            .iter()
            .filter(|(_, record)| record.cpfp.is_some())
            .map(|(txid, record)| (*txid, record.watched_inputs()))
            .collect();
        for (txid, inputs) in watched {
            match self.read_parent(txid, &inputs).await {
                Ok((spent_inputs, status, tip)) => {
                    // The mark is read under the same lock that applies the event, so a bump
                    // that started after the status read still counts as in flight.
                    let mut parents = self.parents.lock().await;
                    let bump_in_flight = parents
                        .get(&txid)
                        .is_some_and(|record| record.bump_in_flight());
                    let event = ParentEvent::Reconciled {
                        spent_inputs,
                        status,
                        tip,
                        rules: self.rules,
                        bump_in_flight,
                    };
                    if apply_event(&mut parents, txid, event) {
                        recovering.insert(txid);
                    }
                }
                Err(err) => {
                    warn!(%txid, %err, "could not reconcile parent; the next block retries")
                }
            }
        }
        recovering
    }

    /// Restarts the burial of every seen conflict.
    async fn note_reorg(&self) {
        for record in self.parents.lock().await.values_mut() {
            record.apply(ParentEvent::Reorged);
        }
    }

    /// Reads what one reconcile needs for `txid`: the spent inputs, the status, and the tip, in
    /// the order that [`ParentEvent::Reconciled`] states.
    async fn read_parent(
        &self,
        txid: Txid,
        inputs: &[OutPoint],
    ) -> Result<(BTreeSet<OutPoint>, TxStatus, u64), ClientError> {
        let mut spent_inputs = BTreeSet::new();
        for outpoint in inputs {
            if self.chain.is_spent_on_chain(*outpoint).await? {
                spent_inputs.insert(*outpoint);
            }
        }
        let status = self.chain.fetch_status(txid).await?;
        Ok((spent_inputs, status, self.chain.tip_height().await?))
    }

    /// Whether a confirmed transaction spends an input of `tx`.
    async fn has_spent_input(&self, tx: &Transaction) -> Result<bool, ClientError> {
        for input in &tx.input {
            if self.chain.is_spent_on_chain(input.previous_output).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Inserts a record for a job, or merges the job into the record that already tracks its
    /// transaction.
    ///
    /// A duplicate drive job keeps the live CPFP state of the existing record, including the
    /// lease of the last child. The duty retry tick re-emits publishes while the state machine
    /// waits for burial. A fresh record there drops that lease and strands its inputs.
    ///
    /// `subscription` is what the job opened before its first read. A bump task can remove the
    /// record that the job found during that read, and the insert then opens the subscription
    /// here. An event in that gap is not delivered. The next block reconcile reads a CPFP
    /// parent.
    // FIXME: <https://alpenlabs.atlassian.net/browse/STR-2687>
    // Handle the race where the relevant event may already have happened before the
    // subscription is established, for a record without CPFP.
    async fn track(
        &self,
        tx: Transaction,
        stage: Stage,
        cpfp: Option<CpfpStrategy>,
        listener: Listener,
        subscription: Option<Subscription<TxEvent>>,
        active_tx_subs: &mut ActiveSubscriptions,
    ) {
        let txid = tx.compute_txid();
        {
            let mut guard = self.parents.lock().await;
            if guard.contains_key(&txid) {
                apply_event(&mut guard, txid, ParentEvent::JobJoined(listener));
                return;
            }
        }
        // Only this loop inserts, so no record appears after the check.
        let subscription = match subscription {
            Some(subscription) => subscription,
            None => self.chain.subscribe(&tx).await,
        };
        let (subscription, abort) = abortable(subscription);
        active_tx_subs.push(subscription);
        let mut record = ParentRecord::new(tx, stage, cpfp, abort);
        record.listeners.push(listener);
        self.parents.lock().await.insert(txid, record);
    }

    /// Handles one new job: reads what the node knows, then answers, tracks, or broadcasts.
    ///
    /// A new subscription opens before the read, so no event falls between the two, apart from
    /// the case that [`Self::track`] states. A record already owns a subscription, and a duty
    /// retry must not open a filter per attempt. A read that fails is treated as an unknown
    /// transaction, and the node decides at the broadcast.
    async fn handle_job(&self, job: TxDriveJob, active_tx_subs: &mut ActiveSubscriptions) {
        let TxDriveJob {
            tx,
            mut listener,
            cpfp,
        } = job;
        let cpfp = cpfp.filter(|_| self.bumper.is_some());
        let txid = tx.compute_txid();
        let tracked = self.parents.lock().await.contains_key(&txid);
        let subscription = if tracked {
            None
        } else {
            Some(self.chain.subscribe(&tx).await)
        };

        let status = match self.chain.fetch_status(txid).await {
            Ok(status) => status,
            Err(err) => {
                warn!(%txid, %err, "could not read the transaction; broadcasting it");
                TxStatus::Unknown
            }
        };
        if status != TxStatus::Unknown {
            // A record for this txid learns the status too, so the job and the bump after it do
            // not act on an old stage.
            apply_event(
                &mut *self.parents.lock().await,
                txid,
                ParentEvent::Status(status.clone()),
            );

            if (listener.condition)(&status) {
                debug!(%txid, %status, "transaction already fulfills the supplied condition, notifying job submitter");
                if listener.respond_on.send(Ok(())).is_err() {
                    error!("could not send response to job submitter");
                }
                return;
            }
            if status.is_buried() {
                let _ = listener.respond_on.send(Err(DriveErr::ConditionUnmet));
                return;
            }

            // The node already knows this transaction. Track it, so this caller hears about
            // later status changes, and so CPFP bumps resume for a parent that an earlier
            // incarnation broadcast and that is still in the mempool.
            let stage = if status.is_mined() {
                Stage::Mined
            } else {
                Stage::Unconfirmed
            };
            let bump_now = cpfp
                .as_ref()
                .is_none_or(|cpfp| cpfp.first_bump == FirstBump::AtPublish);
            self.track(tx, stage, cpfp, listener, subscription, active_tx_subs)
                .await;
            if stage == Stage::Unconfirmed && bump_now {
                self.spawn_bump(txid, BumpFollowUp::Wait);
            }
            return;
        }

        match self.chain.broadcast(&tx).await {
            Ok(txid) => {
                info!(%txid, "broadcasted transaction successfully");
                let bump_now = cpfp
                    .as_ref()
                    .is_none_or(|cpfp| cpfp.first_bump == FirstBump::AtPublish);
                let stage = Stage::Unconfirmed;
                self.track(tx, stage, cpfp, listener, subscription, active_tx_subs)
                    .await;
                if bump_now {
                    self.spawn_bump(txid, BumpFollowUp::Wait);
                }
            }
            // Bare broadcast failed. Most commonly the parent's own fee rate is below the
            // mempool's minimum and a CPFP child can carry it in via `submitpackage` (package
            // validation is more lenient than single-tx acceptance). The next finished bump
            // decides this caller, through `Listener::carried`. A spent input takes no package
            // attempt: no child of this parent can enter a mempool, and each retry of the duty
            // costs a signing round.
            //
            // TODO: <https://alpenlabs.atlassian.net/browse/STR-2689>
            // Distinguish invalid transactions and notify the job submitter instead of
            // treating them like fee-bumping work.
            Err(err) if cpfp.is_some() => {
                match self.has_spent_input(&tx).await {
                    Ok(false) => {}
                    Ok(true) => {
                        warn!(%txid, %err, "bare broadcast failed and an input is spent on chain");
                        let _ = listener.respond_on.send(Err(DriveErr::PublishFailed(err)));
                        return;
                    }
                    Err(read_err) => {
                        // A failed read never blocks a publish: the package attempt decides.
                        warn!(%txid, %read_err, "could not read the inputs of the transaction");
                    }
                }
                warn!(%txid, %err, "bare broadcast failed; attempting CPFP package fallback");
                listener.carried = Some(err);
                let stage = Stage::Unconfirmed;
                self.track(tx, stage, cpfp, listener, subscription, active_tx_subs)
                    .await;
                self.spawn_bump(txid, BumpFollowUp::Wait);
            }
            Err(err) => {
                error!(%txid, ?tx, %err, "could not submit transaction");
                if listener
                    .respond_on
                    .send(Err(DriveErr::PublishFailed(err)))
                    .is_err()
                {
                    error!("could not send error response to job submitter");
                }
            }
        }
    }

    /// The driver loop.
    async fn run(
        self,
        new_jobs: UnboundedReceiver<TxDriveJob>,
        mut block_subscription: Subscription<BlockEvent>,
        bump_check_interval: Option<Duration>,
    ) {
        let mut new_jobs_receiver_stream = UnboundedReceiverStream::new(new_jobs);
        // Each subscription enters through `abortable`, so the record that owns it can
        // end it. `SelectAll` drops a stream that finishes.
        let mut active_tx_subs = ActiveSubscriptions::new();
        // Timer that fires every `bump_check_interval`, when there is a bumper. A parent with a
        // live child at a sufficient rate costs the bumper one probe and no wallet call. A parent
        // whose probe reports the output unspent is fully rebuilt (wallet build + sign +
        // submitpackage), because a silently-evicted child is invisible and the tick is what
        // revives it.
        let mut bump_tick = bump_check_interval.map(tokio::time::interval);
        if let Some(tick) = bump_tick.as_mut() {
            // `Interval::tick` fires immediately on first call. Burn it so the first effective
            // bump tick is one full interval after construction.
            tick.tick().await;
        }
        loop {
            select! {
                Some(job) = new_jobs_receiver_stream.next().fuse() => {
                    self.handle_job(job, &mut active_tx_subs).await;
                }
                Some(event) = active_tx_subs.next().fuse() => {
                    let txid = event.rawtx.compute_txid();
                    let status = ParentEvent::Status(event.status);
                    if apply_event(&mut *self.parents.lock().await, txid, status) {
                        self.spawn_bump(txid, BumpFollowUp::ResubmitBare(Some(event.rawtx)));
                    }
                }
                Some(event) = block_subscription.next().fuse() => {
                    // A block reaches burial in the same step that connects another block, so
                    // a `Buried` block event brings no second tip change. A block that leaves
                    // the chain does, and a reconcile sees its parents leave `Mined`.
                    if event.status != BlockStatus::Buried {
                        if event.status == BlockStatus::Uncled {
                            self.note_reorg().await;
                        }
                        let recovering = self.reconcile().await;
                        self.spawn_batch_bump(recovering).await;
                    }
                }
                _ = next_tick(bump_tick.as_mut()).fuse() => {
                    self.spawn_batch_bump(HashSet::new()).await;
                }
            }
        }
    }
}

/// Waits for the next tick of `interval`, or forever when there is none.
async fn next_tick(interval: Option<&mut tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
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
    /// Initializes a TxDriver that publishes bare transactions. A job that asks for CPFP runs as a
    /// bare job.
    pub async fn new(zmq_client: BtcNotifyClient<Connected>, rpc_client: BitcoinClient) -> Self {
        Self::start(zmq_client, rpc_client, None).await
    }

    /// Initializes a TxDriver with CPFP fee bumping.
    ///
    /// Jobs submitted via [`Self::drive_with_cpfp`] get a CPFP child from `bumper`:
    ///
    /// * On mempool eviction (per-tx ZMQ `Unknown` event): the bumper rebuilds the child and
    ///   RBF-submits `[parent, child]` as a package.
    /// * On each new block and each `bump_check_interval`: the driver walks every active CPFP
    ///   parent that has not confirmed and runs the same bump, deadline parents first.
    ///
    /// On each new block the driver also reconciles every CPFP parent against the node. It stops
    /// on an unconfirmed parent when a buried transaction spends one of its inputs.
    pub async fn with_cpfp(
        zmq_client: BtcNotifyClient<Connected>,
        rpc_client: BitcoinClient,
        bumper: Arc<dyn CpfpBumper>,
        bump_check_interval: Duration,
    ) -> Self {
        Self::start(zmq_client, rpc_client, Some((bumper, bump_check_interval))).await
    }

    async fn start(
        zmq_client: BtcNotifyClient<Connected>,
        rpc_client: BitcoinClient,
        bumper: Option<(Arc<dyn CpfpBumper>, Duration)>,
    ) -> Self {
        let bury_depth = zmq_client.bury_depth() as u64;
        let block_subscription = zmq_client.subscribe_blocks().await;
        let chain = Arc::new(NodeAccess {
            zmq_client,
            rpc_client,
        });
        let rules = GiveUpRules { bury_depth };
        Self::spawn(chain, block_subscription, bumper, rules)
    }

    /// Starts the driver loop over `chain`. `bumper` carries the bump interval with it: a driver
    /// without a bumper has no bump to run on a tick.
    fn spawn(
        chain: Arc<dyn ChainAccess>,
        block_subscription: Subscription<BlockEvent>,
        bumper: Option<(Arc<dyn CpfpBumper>, Duration)>,
        rules: GiveUpRules,
    ) -> Self {
        let (new_jobs_sender, new_jobs) = unbounded_channel::<TxDriveJob>();
        let (bumper, bump_check_interval) = bumper.unzip();
        let core = DriverCore {
            chain,
            bumper,
            parents: Arc::new(Mutex::new(HashMap::new())),
            rules,
        };
        let driver =
            tokio::task::spawn(core.run(new_jobs, block_subscription, bump_check_interval));

        TxDriver {
            new_jobs_sender,
            driver,
        }
    }

    /// Instructs the TxDriver to drive a new transaction to confirmation without CPFP.
    pub async fn drive(
        &self,
        tx: Transaction,
        condition: impl Fn(&TxStatus) -> bool + Send + 'static,
    ) -> Result<(), DriveErr> {
        self.drive_inner(tx, condition, None).await
    }

    /// Instructs the TxDriver to drive a new transaction to confirmation with CPFP
    /// fee-bumping. The driver runs a bump immediately, then on each new block, tick, and
    /// mempool eviction until the parent confirms or the driver gives up on it.
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
        let (sender, receiver) = oneshot::channel();
        self.new_jobs_sender
            .send(TxDriveJob {
                tx,
                listener: Listener::new(Box::new(condition), sender),
                cpfp,
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
    /// Aborts the main driver task. Each in-flight bump task is detached, and a detached
    /// bump runs to the end of its current attempt. The records map is behind an [`Arc`]: the
    /// driver task drops its clone, and the map goes when the last bump task ends.
    ///
    /// At process shutdown the runtime tears those tasks down. A restart of `TxDriver` inside
    /// one process can race the bump tasks of the previous instance for a short time. That
    /// race is safe: the records map belongs to one `TxDriver`, so an old task reads only its
    /// own map.
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{absolute, transaction, Amount, ScriptBuf, Transaction, TxOut};

    use super::broadcast_options;

    fn tx_with_outputs(output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output,
        }
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
mod e2e_tests {
    use std::{collections::VecDeque, path::PathBuf, sync::Arc};

    use algebra::predicate;
    use bitcoin::{
        absolute, transaction, Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxOut, Witness,
    };
    use bitcoind_async_client::Client as BitcoinClient;
    use corepc_node::{client::client_sync::Auth, vtype::FundRawTransaction, CookieValues, Output};
    use futures::join;
    use serial_test::serial;
    use strata_bridge_common::logging;
    use strata_bridge_test_utils::prelude::wait_for_height;
    use tracing::{debug, info};

    use super::*;
    use crate::{client::BlockFetcher, config::BtcNotifyConfig};

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2692>
    // Remove this once rust-bitcoin@0.33.x lands; it works around a rust-bitcoin bug.
    pub(crate) const BIP34_MIN_BLOCKS: usize = 17;

    fn setup_fetcher(rpc_url: &str, cookie_file: PathBuf) -> impl BlockFetcher<Error = String> {
        struct Fetcher(corepc_node::Client);

        #[async_trait::async_trait]
        impl BlockFetcher for Fetcher {
            type Error = String;

            async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
                let hash = self
                    .0
                    .get_block_hash(height)
                    .map_err(|e| e.to_string())?
                    .block_hash()
                    .expect("must be valid hash");
                let block = self.0.get_block(hash).map_err(|e| e.to_string())?;

                Ok(block)
            }
        }

        let auth = Auth::CookieFile(cookie_file);
        let client = corepc_node::Client::new_with_auth(rpc_url, auth)
            .expect("must be able to create client");

        Fetcher(client)
    }

    async fn setup() -> Result<(TxDriver, corepc_node::Node), Box<dyn std::error::Error>> {
        let mut bitcoin_conf = corepc_node::Conf::default();
        bitcoin_conf.enable_zmq = true;

        // TODO: <https://alpenlabs.atlassian.net/browse/STR-2681>
        // Use dynamic port allocation so these tests can run in parallel.
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
            // NOTE: (@Rajil1213) without this, the node will respond with status code 500
            // when rebroadcasting or querying for mined transactions, causing idempotence tests to
            // fail or become flaky.
            "-txindex=1".to_string(),
        ];
        bitcoin_conf.args.extend(args.iter().map(String::as_str));
        let bitcoind = corepc_node::Node::with_conf("bitcoind", &bitcoin_conf)?;

        bitcoind
            .client
            .generate_to_address(BIP34_MIN_BLOCKS, &bitcoind.client.new_address()?)?;

        debug!("corepc_node::Node initialized");

        let cfg = BtcNotifyConfig::default()
            .with_hashblock_connection_string(hash_block_socket)
            .with_hashtx_connection_string(hash_tx_socket)
            .with_rawblock_connection_string(raw_block_socket)
            .with_rawtx_connection_string(raw_tx_socket)
            .with_sequence_connection_string(sequence_socket);

        let zmq_client = BtcNotifyClient::new(&cfg, VecDeque::new());
        let start_height = bitcoind.client.get_block_count()?.0;
        let cookie_file = bitcoind.params.cookie_file.clone();
        let fetcher = setup_fetcher(&bitcoind.rpc_url(), cookie_file);
        let zmq_client = zmq_client.connect(start_height, fetcher).await?;
        debug!("BtcNotifyClient initialized");

        let CookieValues { user, password } = bitcoind
            .params
            .get_cookie_values()
            .expect("can read cookie")
            .expect("can parse cookie");
        let auth = bitcoind_async_client::Auth::UserPass(user, password);
        let rpc_client = BitcoinClient::new(bitcoind.rpc_url(), auth, None, None, None)
            .expect("can set up rpc client");
        debug!("bitcoin_async_client::Client initialized");

        let tx_driver = TxDriver::new(zmq_client, rpc_client).await;
        debug!("TxDriver initialized");

        Ok((tx_driver, bitcoind))
    }

    #[tokio::test]
    #[serial]
    async fn tx_drive_idempotence() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("tx_drive_idempotence");

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
        let out = Output::new(new_address.clone(), Amount::from_btc(1.0)?);
        // Get hex string directly - don't use into_model() as 0-input transactions
        // can't be deserialized due to segwit marker ambiguity
        let raw_hex = bitcoind.client.create_raw_transaction(&[], &[out])?.0;
        debug!(%raw_hex, "created raw transaction");

        debug!("funding raw transaction");
        // Use call() directly to pass hex string since fund_raw_transaction expects &Transaction
        let funded_result: FundRawTransaction = bitcoind
            .client
            .call("fundrawtransaction", &[raw_hex.into()])?;
        let funded = funded_result.into_model()?.tx;
        debug!(funded=%funded.compute_txid(), "funded raw transaction");

        debug!("signing raw transaction");
        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&funded)?
            .into_model()?
            .tx;
        debug!(signed=%signed.compute_txid(), "signed raw transaction");

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
        logging::init_from_env("tx_drive_idempotence");

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
        let outs = vec![Output::new(new_address, Amount::from_btc(1.0)?)];
        // Get hex string directly - don't use into_model() as 0-input transactions
        // can't be deserialized due to segwit marker ambiguity
        let raw_hex = bitcoind.client.create_raw_transaction(&[], &outs)?.0;
        debug!(%raw_hex, "created raw transaction");

        debug!("funding raw transaction");
        // Use call() directly to pass hex string since fund_raw_transaction expects &Transaction
        let funded_result: FundRawTransaction = bitcoind
            .client
            .call("fundrawtransaction", &[raw_hex.into()])?;
        let funded = funded_result.into_model()?.tx;
        debug!(funded=%funded.compute_txid(), "funded raw transaction");

        debug!("signing raw transaction");
        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&funded)?
            .into_model()?
            .tx;
        debug!(signed=%signed.compute_txid(), "signed raw transaction");

        info!("driving to mempool");
        driver
            .drive(signed, predicate::eq(TxStatus::Mempool))
            .await?;
        info!("transaction appeared in mempool");

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn tx_drive_op_return_burn() -> Result<(), Box<dyn std::error::Error>> {
        logging::init_from_env("tx_drive_op_return_burn");

        let (driver, bitcoind) = setup().await?;

        let new_address = bitcoind.client.new_address()?;
        let blocks = bitcoind
            .client
            .generate_to_address(101, &new_address)?
            .into_model()?;
        debug!("waiting for test funds to mature");
        wait_for_height(&bitcoind, 101).await?;
        debug!("test funds matured");

        let spendable_block = bitcoind.client.get_block(
            *blocks
                .0
                .first()
                .expect("generate_to_address must return mined block hashes"),
        )?;
        let coinbase_tx = spendable_block
            .coinbase()
            .expect("mined block must contain a coinbase transaction");

        let burn_amount = Amount::from_sat(1_000);
        let fee = Amount::from_sat(10_000);
        let change_amount = coinbase_tx.output[0].value - burn_amount - fee;
        let change_address = bitcoind.client.new_address()?;
        let unsigned = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(coinbase_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![
                TxOut {
                    value: burn_amount,
                    script_pubkey: ScriptBuf::new_op_return([1u8; 32]),
                },
                TxOut {
                    value: change_amount,
                    script_pubkey: change_address.script_pubkey(),
                },
            ],
        };

        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&unsigned)?
            .into_model()?
            .tx;

        let err = bitcoind
            .client
            .send_raw_transaction(&signed)
            .expect_err("default maxburnamount must reject OP_RETURN burns");
        let err = err.to_string();
        assert!(
            err.contains("maxburnamount") || err.contains("max-burn-amount"),
            "unexpected sendrawtransaction error: {err}"
        );

        info!("driving OP_RETURN burn to mempool");
        driver
            .drive(signed.clone(), predicate::eq(TxStatus::Mempool))
            .await?;
        info!("OP_RETURN burn transaction appeared in mempool");

        Ok(())
    }
}

/// Test doubles that the driver test modules share.
#[cfg(test)]
mod test_support {
    use std::{
        collections::HashMap,
        sync::{atomic::AtomicUsize, Mutex as StdMutex},
    };

    use bitcoin::{
        absolute, hashes::Hash, transaction::Version, OutPoint, ScriptBuf, Sequence, TxIn, TxOut,
        Witness,
    };
    use strata_bridge_primitives::cpfp::ChildSpend;
    use tokio::sync::mpsc::unbounded_channel;

    use super::*;

    /// A bumper that reports one outcome, stores `stored` in the parent's state, and records the
    /// order of its parents. With a gate, each bump waits for one permit, so that a test can
    /// change a record during a bump.
    #[derive(Debug)]
    pub(super) struct FakeBumper {
        outcome: BumpOutcome,
        stored: Option<&'static str>,
        gate: Option<Arc<tokio::sync::Semaphore>>,
        calls: AtomicUsize,
        bumped: StdMutex<Vec<Txid>>,
    }

    impl FakeBumper {
        pub(super) fn reporting(outcome: BumpOutcome) -> Self {
            Self {
                outcome,
                stored: None,
                gate: None,
                calls: AtomicUsize::new(0),
                bumped: StdMutex::new(Vec::new()),
            }
        }

        pub(super) fn storing(outcome: BumpOutcome, stored: &'static str) -> Self {
            Self {
                stored: Some(stored),
                ..Self::reporting(outcome)
            }
        }

        /// A bumper that stores `stored`, with a gate that starts closed.
        pub(super) fn gated(
            outcome: BumpOutcome,
            stored: &'static str,
        ) -> (Self, Arc<tokio::sync::Semaphore>) {
            let gate = Arc::new(tokio::sync::Semaphore::new(0));
            let bumper = Self {
                gate: Some(gate.clone()),
                ..Self::storing(outcome, stored)
            };
            (bumper, gate)
        }

        pub(super) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl CpfpBumper for FakeBumper {
        async fn bump(
            &self,
            parent: &Transaction,
            _strategy: &CpfpStrategy,
            state: &mut BumpState,
        ) -> BumpOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.bumped
                .lock()
                .expect("not poisoned")
                .push(parent.compute_txid());
            if let Some(gate) = &self.gate {
                gate.acquire().await.expect("the gate stays open").forget();
            }
            if let Some(stored) = self.stored {
                *state = BumpState::new(stored);
            }
            self.outcome
        }
    }

    /// The node that a test scripts: statuses, on-chain spends, the tip, and open subscriptions.
    #[derive(Default)]
    pub(super) struct FakeChain {
        pub(super) statuses: StdMutex<HashMap<Txid, TxStatus>>,
        pub(super) spent: StdMutex<BTreeSet<OutPoint>>,
        pub(super) tip: StdMutex<u64>,
        pub(super) reject_broadcast: AtomicBool,
        pub(super) broadcasts: AtomicUsize,
        pub(super) subscribers: StdMutex<HashMap<Txid, UnboundedSender<TxEvent>>>,
        pub(super) subscriptions: AtomicUsize,
        /// Fails every status read while set.
        pub(super) rpc_down: AtomicBool,
        /// Moves the tip during a spend read, as a block that connects between two reads does.
        pub(super) tip_during_spend_read: StdMutex<Option<u64>>,
    }

    impl FakeChain {
        pub(super) fn set_status(&self, txid: Txid, status: TxStatus) {
            self.statuses
                .lock()
                .expect("not poisoned")
                .insert(txid, status);
        }

        pub(super) fn set_tip(&self, tip: u64) {
            *self.tip.lock().expect("not poisoned") = tip;
        }

        /// Delivers one ZMQ event for `tx`.
        pub(super) fn emit(&self, tx: &Transaction, status: TxStatus) {
            let event = TxEvent {
                rawtx: tx.clone(),
                status,
            };
            self.subscribers.lock().expect("not poisoned")[&tx.compute_txid()]
                .send(event)
                .expect("the subscription is open");
        }
    }

    #[async_trait]
    impl ChainAccess for FakeChain {
        async fn subscribe(&self, tx: &Transaction) -> Subscription<TxEvent> {
            self.subscriptions.fetch_add(1, Ordering::SeqCst);
            let (sender, receiver) = unbounded_channel();
            self.subscribers
                .lock()
                .expect("not poisoned")
                .insert(tx.compute_txid(), sender);
            Subscription::from_receiver(receiver)
        }

        async fn fetch_status(&self, txid: Txid) -> Result<TxStatus, ClientError> {
            if self.rpc_down.load(Ordering::SeqCst) {
                return Err(ClientError::Other("connection refused".into()));
            }
            Ok(self
                .statuses
                .lock()
                .expect("not poisoned")
                .get(&txid)
                .cloned()
                .unwrap_or(TxStatus::Unknown))
        }

        async fn is_spent_on_chain(&self, outpoint: OutPoint) -> Result<bool, ClientError> {
            if let Some(tip) = *self.tip_during_spend_read.lock().expect("not poisoned") {
                self.set_tip(tip);
            }
            Ok(self.spent.lock().expect("not poisoned").contains(&outpoint))
        }

        async fn tip_height(&self) -> Result<u64, ClientError> {
            Ok(*self.tip.lock().expect("not poisoned"))
        }

        async fn broadcast(&self, tx: &Transaction) -> Result<Txid, ClientError> {
            self.broadcasts.fetch_add(1, Ordering::SeqCst);
            if self.reject_broadcast.load(Ordering::SeqCst) {
                return Err(ClientError::Other("bare broadcast rejected".into()));
            }
            let txid = tx.compute_txid();
            self.set_status(txid, TxStatus::Mempool);
            Ok(txid)
        }
    }

    /// The input of every parent that `parent` builds, for a `seed`.
    pub(super) fn input_of(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([seed; 32]),
            vout: 0,
        }
    }

    /// A parent with one input. Two seeds give two txids.
    pub(super) fn parent(seed: u8) -> Transaction {
        Transaction {
            version: Version::non_standard(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: input_of(seed),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(330),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    pub(super) fn strategy(parent: &Transaction, deadline: DeadlineClass) -> CpfpStrategy {
        CpfpStrategy {
            spend: ChildSpend::owned_output(OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            }),
            parent_fee: Amount::ZERO,
            deadline,
            first_bump: FirstBump::AtPublish,
        }
    }

    pub(super) const RULES: GiveUpRules = GiveUpRules { bury_depth: 6 };

    /// Builds a record whose CPFP state is fresh and whose subscription handle is inert.
    pub(super) fn test_record(
        parent: Transaction,
        stage: Stage,
        deadline: DeadlineClass,
    ) -> ParentRecord {
        let strategy = strategy(&parent, deadline);
        ParentRecord::new(parent, stage, Some(strategy), AbortHandle::new_pair().0)
    }

    /// A listener that no status satisfies, paired with the receiver that hears its outcome.
    pub(super) fn never_listener() -> (Listener, oneshot::Receiver<Result<(), DriveErr>>) {
        let (respond_on, receiver) = oneshot::channel();
        (Listener::new(Box::new(|_| false), respond_on), receiver)
    }

    /// A listener whose bare broadcast failed, and the receiver that hears its outcome.
    pub(super) fn carried_listener() -> (Listener, oneshot::Receiver<Result<(), DriveErr>>) {
        let (mut listener, receiver) = never_listener();
        listener.carried = Some(ClientError::Other("bare broadcast rejected".into()));
        (listener, receiver)
    }

    pub(super) fn mined() -> TxStatus {
        TxStatus::Mined {
            blockhash: BlockHash::all_zeros(),
            height: 100,
        }
    }

    pub(super) fn buried() -> TxStatus {
        TxStatus::Buried {
            blockhash: BlockHash::all_zeros(),
            height: 100,
        }
    }
}

/// Tests of the pure record transitions.
#[cfg(test)]
mod record_tests {
    use bitcoin::hashes::Hash;
    use proptest::prelude::*;

    use super::{test_support::*, *};

    fn reconciled(tip: u64, status: TxStatus, spent: &[OutPoint]) -> ParentEvent {
        ParentEvent::Reconciled {
            spent_inputs: spent.iter().copied().collect(),
            status,
            tip,
            rules: RULES,
            bump_in_flight: false,
        }
    }

    fn removes(actions: &[ParentAction]) -> bool {
        actions
            .iter()
            .any(|action| matches!(action, ParentAction::Remove))
    }

    fn recovers(actions: &[ParentAction]) -> bool {
        actions
            .iter()
            .any(|action| matches!(action, ParentAction::Recover))
    }

    fn answers<'a>(
        actions: &'a [ParentAction],
    ) -> impl Iterator<Item = &'a Result<(), DriveErr>> + 'a {
        actions.iter().filter_map(|action| match action {
            ParentAction::Answer(_, result) => Some(result),
            _ => None,
        })
    }

    #[test]
    fn confirmed_status_buries_at_the_bury_depth() {
        let blockhash = BlockHash::all_zeros();

        assert_eq!(confirmed_status(1, blockhash, 100, 6), mined());
        assert_eq!(confirmed_status(5, blockhash, 100, 6), mined());
        assert_eq!(confirmed_status(6, blockhash, 100, 6), buried());
        // A bury depth of zero buries a block when it connects.
        assert_eq!(confirmed_status(1, blockhash, 100, 0), buried());
    }

    #[test]
    fn the_subscription_filter_matches_another_witness_and_no_other_txid() {
        let tx = parent(1);
        let mut variant = tx.clone();
        variant.input[0].witness.push([1]);
        assert_ne!(tx, variant);
        let mut same_first_input = tx.clone();
        same_first_input.lock_time = bitcoin::absolute::LockTime::from_consensus(1);

        let filter = matches_txid(&tx);

        assert!(filter(&variant));
        assert!(!filter(&parent(2)));
        assert!(!filter(&same_first_input));
    }

    /// A parent in a block says nothing about its child. The child can be live, so the lease
    /// stays with the record.
    #[test]
    fn a_mined_status_stops_the_bumps_and_keeps_the_lease() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);
        record.cpfp.as_mut().expect("cpfp").state = BumpState::new("lease");

        let actions = record.apply(ParentEvent::Status(mined()));

        assert!(actions.is_empty());
        assert_eq!(record.stage, Stage::Mined);
        assert!(!record.is_bumpable());
        let cpfp = record.cpfp.as_ref().expect("cpfp");
        assert_eq!(cpfp.state.get::<&str>(), Some(&"lease"));
    }

    #[test]
    fn a_reorg_wakes_a_mined_record() {
        for status in [TxStatus::Mempool, TxStatus::Unknown] {
            let mut record = test_record(parent(1), Stage::Mined, DeadlineClass::NoDeadline);

            let actions = record.apply(ParentEvent::Status(status.clone()));

            assert!(record.is_bumpable(), "status = {status}");
            assert_eq!(recovers(&actions), status == TxStatus::Unknown);
        }
    }

    #[test]
    fn a_buried_status_removes_the_record_and_answers_every_listener() {
        let mut record = test_record(parent(1), Stage::Mined, DeadlineClass::NoDeadline);
        let (unmet, _unmet_receiver) = never_listener();
        let (met, _met_receiver) = oneshot::channel();
        record.listeners.push(unmet);
        record
            .listeners
            .push(Listener::new(Box::new(TxStatus::is_buried), met));

        let actions = record.apply(ParentEvent::Status(buried()));

        assert!(removes(&actions));
        let results: Vec<_> = answers(&actions).collect();
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|result| result.is_ok()));
        assert!(results
            .iter()
            .any(|result| matches!(result, Err(DriveErr::ConditionUnmet))));
    }

    #[test]
    fn a_duplicate_job_keeps_the_tx_and_the_live_cpfp_state() {
        let tx = parent(1);
        let mut variant = tx.clone();
        variant.input[0].witness.push([1]);
        let mut record = test_record(tx.clone(), Stage::Unconfirmed, DeadlineClass::Deadline);
        record.cpfp.as_mut().expect("cpfp").state = BumpState::new("lease");
        let (listener, _receiver) = never_listener();

        record.apply(ParentEvent::JobJoined(listener));

        let cpfp = record.cpfp.as_ref().expect("cpfp");
        assert_eq!(cpfp.state.get::<&str>(), Some(&"lease"));
        assert_eq!(cpfp.strategy.deadline, DeadlineClass::Deadline);
        assert_eq!(record.tx, tx);
        assert_eq!(record.listeners.len(), 1);
    }

    #[test]
    fn a_job_does_not_rearm_a_parent_that_lost_its_cpfp_state() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        record.cpfp = None;
        let (listener, _receiver) = never_listener();

        record.apply(ParentEvent::JobJoined(listener));

        assert!(!record.is_bumpable());
    }

    #[test]
    fn a_carried_job_with_no_bump_to_carry_it_hears_its_error() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        record.cpfp = None;
        let (listener, _receiver) = carried_listener();

        let actions = record.apply(ParentEvent::JobJoined(listener));

        assert!(matches!(
            answers(&actions).next(),
            Some(Err(DriveErr::PublishFailed(_)))
        ));
        assert!(record.listeners.is_empty());
    }

    fn no_package() -> ParentEvent {
        ParentEvent::BumpFinished {
            state: BumpState::default(),
            outcome: BumpOutcome::NoPackage,
        }
    }

    fn package_out() -> ParentEvent {
        ParentEvent::BumpFinished {
            state: BumpState::default(),
            outcome: BumpOutcome::Submitted,
        }
    }

    #[test]
    fn a_bump_with_no_package_expires_a_record_that_only_carried_jobs_wait_on() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);
        let (first, _first_receiver) = carried_listener();
        let (second, _second_receiver) = carried_listener();
        record.listeners.push(first);
        record.listeners.push(second);

        let actions = record.apply(no_package());

        assert!(
            !removes(&actions),
            "the state can hold a live child's lease"
        );
        assert_eq!(record.stage, Stage::Expired);
        let errors = answers(&actions)
            .filter(|result| matches!(result, Err(DriveErr::PublishFailed(_))))
            .count();
        assert_eq!(errors, 2, "every carried job hears its broadcast error");

        let mempool = reconciled(101, TxStatus::Mempool, &[]);
        assert!(
            !removes(&record.apply(mempool)),
            "a package that landed keeps the lease of its child"
        );
        let actions = record.apply(reconciled(102, TxStatus::Unknown, &[]));
        assert!(removes(&actions), "a parent in no mempool ends the record");
        assert!(!recovers(&actions), "and takes no resubmission");
    }

    #[test]
    fn a_bump_with_no_package_keeps_a_record_that_another_job_waits_on() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);
        let (other, _other_receiver) = never_listener();
        let (carried, _carried_receiver) = carried_listener();
        record.listeners.push(other);
        record.listeners.push(carried);

        let actions = record.apply(no_package());

        assert!(!removes(&actions));
        assert_eq!(answers(&actions).count(), 1, "only the failed job hears it");
        assert_eq!(record.listeners.len(), 1);
    }

    #[test]
    fn a_bump_with_no_package_leaves_a_record_with_no_carried_job_alone() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);

        assert!(record.apply(no_package()).is_empty());
    }

    #[test]
    fn a_package_turns_a_carried_job_into_a_plain_listener() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);
        let (carried, _receiver) = carried_listener();
        record.listeners.push(carried);

        assert!(record.apply(package_out()).is_empty());
        assert!(
            record.apply(no_package()).is_empty(),
            "a later failure says nothing"
        );
        assert_eq!(record.listeners.len(), 1);
    }

    #[test]
    fn a_status_from_the_network_clears_a_carried_job() {
        for status in [TxStatus::Mempool, mined()] {
            let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);
            let (carried, _receiver) = carried_listener();
            record.listeners.push(carried);

            record.apply(ParentEvent::Status(status));

            assert!(record.apply(no_package()).is_empty());
            assert_eq!(record.listeners.len(), 1);
        }
    }

    /// A bump that ends after its parent left `Unconfirmed` can have a child in a mempool, so
    /// its lease reaches the record at every stage.
    #[test]
    fn a_finished_bump_stores_its_state_at_every_stage() {
        for stage in [Stage::Unconfirmed, Stage::Expired, Stage::Mined] {
            let mut record = test_record(parent(1), stage, DeadlineClass::NoDeadline);

            record.apply(ParentEvent::BumpFinished {
                state: BumpState::new("lease"),
                outcome: BumpOutcome::NoPackage,
            });

            let cpfp = record.cpfp.as_ref().expect("cpfp");
            assert_eq!(
                cpfp.state.get::<&str>(),
                Some(&"lease"),
                "stage = {stage:?}"
            );
        }
    }

    #[test]
    fn an_unbumpable_parent_loses_its_cpfp_state_and_keeps_its_listeners() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);
        let (listener, _receiver) = never_listener();
        record.listeners.push(listener);

        let actions = record.apply(ParentEvent::BumpFinished {
            state: BumpState::default(),
            outcome: BumpOutcome::Unbumpable,
        });

        assert!(actions.is_empty());
        assert!(record.cpfp.is_none());
        assert_eq!(record.listeners.len(), 1);
    }

    #[test]
    fn a_reconcile_of_a_parent_in_no_mempool_recovers_it() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);

        assert!(recovers(&record.apply(reconciled(
            100,
            TxStatus::Unknown,
            &[]
        ))));
    }

    #[test]
    fn a_parent_gives_up_when_the_conflict_is_buried() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        let (listener, _receiver) = never_listener();
        record.listeners.push(listener);
        let spent = [input_of(1)];

        for tip in 100..106 {
            let actions = record.apply(reconciled(tip, TxStatus::Unknown, &spent));
            assert!(!removes(&actions), "tip = {tip}");
        }

        let actions = record.apply(reconciled(106, TxStatus::Unknown, &spent));
        assert!(removes(&actions));
        assert!(!recovers(&actions), "a dead parent must not go back");
        assert!(matches!(
            answers(&actions).next(),
            Some(Err(DriveErr::ConflictBuried))
        ));
    }

    #[test]
    fn a_reorged_conflict_restarts_its_burial() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        let spent = [input_of(1)];

        record.apply(reconciled(100, TxStatus::Unknown, &spent));
        record.apply(reconciled(104, TxStatus::Mempool, &[]));
        let actions = record.apply(reconciled(106, TxStatus::Unknown, &spent));

        assert!(!removes(&actions));
    }

    /// The parent's own txid comes first: a parent in a block with its inputs spent by itself is
    /// no conflict, under any witness.
    #[test]
    fn a_confirmed_parent_never_reads_as_a_conflict() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        let spent = [input_of(1)];

        for tip in 100..120 {
            let actions = record.apply(reconciled(tip, mined(), &spent));
            assert!(answers(&actions).next().is_none(), "tip = {tip}");
            assert!(!removes(&actions), "tip = {tip}");
        }
    }

    #[test]
    fn a_reconcile_watches_the_inputs_of_an_unconfirmed_cpfp_record_only() {
        let unconfirmed = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        let mined = test_record(parent(1), Stage::Mined, DeadlineClass::Deadline);
        let mut bare = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        bare.cpfp = None;

        assert_eq!(unconfirmed.watched_inputs(), vec![input_of(1)]);
        assert!(bare.watched_inputs().is_empty());
        assert!(mined.watched_inputs().is_empty());
    }

    /// Expiry answers the callers and keeps the record: the parent is in the mempool, so its
    /// child is live, and the lease on the inputs of that child must stay held.
    #[test]
    fn an_expired_parent_in_the_mempool_keeps_the_lease_of_its_live_child() {
        let mut record = expired_record();

        assert_eq!(record.stage, Stage::Expired);
        assert!(!record.is_bumpable());
        let cpfp = record.cpfp.as_ref().expect("cpfp");
        assert_eq!(cpfp.state.get::<&str>(), Some(&"lease"));
        assert!(record
            .apply(reconciled(200, TxStatus::Mempool, &[]))
            .is_empty());
    }

    /// A record whose only caller carried a failed broadcast and heard that no package went out.
    fn expired_record() -> ParentRecord {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);
        let (listener, _receiver) = carried_listener();
        record.apply(ParentEvent::JobJoined(listener));
        record.apply(ParentEvent::BumpFinished {
            state: BumpState::new("lease"),
            outcome: BumpOutcome::NoPackage,
        });
        assert_eq!(record.stage, Stage::Expired);
        record
    }

    /// A ZMQ eviction cannot see a bump in flight, so the reconcile decides.
    #[test]
    fn a_zmq_eviction_leaves_an_expired_record_to_the_reconcile() {
        let mut record = expired_record();

        assert!(record
            .apply(ParentEvent::Status(TxStatus::Unknown))
            .is_empty());
    }

    /// A reorg can move the spender to a new block with no read that shows the output unspent,
    /// so its burial starts over.
    #[test]
    fn a_reorg_restarts_the_burial_of_a_conflict_that_stays_spent() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        let spent = [input_of(1)];
        record.apply(reconciled(100, TxStatus::Unknown, &spent));

        assert!(record.apply(ParentEvent::Reorged).is_empty());
        let actions = record.apply(reconciled(105, TxStatus::Unknown, &spent));
        assert!(!removes(&actions));

        assert!(!removes(&record.apply(reconciled(
            110,
            TxStatus::Unknown,
            &spent
        ))));
        assert!(removes(&record.apply(reconciled(
            111,
            TxStatus::Unknown,
            &spent
        ))));
    }

    /// A child of a parent with a spent input cannot enter a mempool, so the parent takes no
    /// bump and no resubmission until the conflict is decided.
    #[test]
    fn a_parent_with_a_seen_conflict_takes_no_bump_until_a_reorg_undoes_it() {
        let mut record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
        let spent = [input_of(1)];

        let actions = record.apply(reconciled(100, TxStatus::Unknown, &spent));
        assert!(!recovers(&actions));
        assert!(!record.is_bumpable());
        assert!(!recovers(
            &record.apply(ParentEvent::Status(TxStatus::Unknown))
        ));

        let actions = record.apply(reconciled(101, TxStatus::Unknown, &[]));
        assert!(recovers(&actions));
        assert!(record.is_bumpable());
    }

    #[test]
    fn a_job_wakes_an_expired_parent_with_its_lease_and_a_new_wait() {
        let mut record = expired_record();
        let (listener, _receiver) = never_listener();

        record.apply(ParentEvent::JobJoined(listener));

        assert!(record.is_bumpable());
        let cpfp = record.cpfp.as_ref().expect("cpfp");
        assert_eq!(cpfp.state.get::<&str>(), Some(&"lease"));
    }

    #[test]
    fn an_expired_parent_that_confirms_follows_the_chain() {
        let mut record = expired_record();

        record.apply(ParentEvent::Status(mined()));
        assert_eq!(record.stage, Stage::Mined);

        assert!(removes(&record.apply(ParentEvent::Status(buried()))));
    }

    #[test]
    fn a_walk_visits_deadline_parents_first() {
        let map: ParentMap = (1..=8u8)
            .map(|seed| {
                let deadline = if seed % 2 == 0 {
                    DeadlineClass::Deadline
                } else {
                    DeadlineClass::NoDeadline
                };
                let tx = parent(seed);
                (
                    tx.compute_txid(),
                    test_record(tx, Stage::Unconfirmed, deadline),
                )
            })
            .collect();

        let walk = batch_order(&map);

        assert_eq!(walk.len(), 8);
        let is_deadline = |txid: &Txid| {
            map[txid].cpfp.as_ref().expect("cpfp").strategy.deadline == DeadlineClass::Deadline
        };
        assert!(walk[..4].iter().all(is_deadline));
        assert!(!walk[4..].iter().any(is_deadline));
    }

    /// One step of a generated record history.
    #[derive(Debug, Clone)]
    enum Step {
        Status(TxStatus),
        Reconciled {
            blocks: u64,
            status: TxStatus,
            spent: bool,
            bump_in_flight: bool,
        },
        Reorged,
        Listener {
            carried: bool,
        },
        Bump(BumpOutcome),
    }

    fn arb_status() -> impl Strategy<Value = TxStatus> {
        prop_oneof![
            Just(TxStatus::Unknown),
            Just(TxStatus::Mempool),
            Just(mined()),
            Just(buried()),
        ]
    }

    fn arb_step() -> impl Strategy<Value = Step> {
        prop_oneof![
            arb_status().prop_map(Step::Status),
            (0..4u64, arb_status(), any::<bool>(), any::<bool>()).prop_map(
                |(blocks, status, spent, bump_in_flight)| Step::Reconciled {
                    blocks,
                    status,
                    spent,
                    bump_in_flight,
                }
            ),
            Just(Step::Reorged),
            any::<bool>().prop_map(|carried| Step::Listener { carried }),
            prop_oneof![
                Just(BumpOutcome::Submitted),
                Just(BumpOutcome::ParentIsLive),
                Just(BumpOutcome::NoPackage),
                Just(BumpOutcome::Unbumpable),
            ]
            .prop_map(Step::Bump),
        ]
    }

    /// What one generated history did.
    struct History {
        record: ParentRecord,
        added: usize,
        answered: Vec<Result<(), DriveErr>>,
        removed: bool,
    }

    /// Runs `steps` until the record asks for its removal. The record starts with one listener
    /// that burial satisfies, so each removal and each stop reports its reason.
    fn run_steps(mut record: ParentRecord, steps: Vec<Step>) -> History {
        let (respond_on, _seeded) = oneshot::channel();
        record
            .listeners
            .push(Listener::new(Box::new(TxStatus::is_buried), respond_on));
        let mut tip = 100;
        let mut history_added = 1;
        let mut answered = Vec::new();
        let mut receivers = Vec::new();
        let mut removed = false;
        for step in steps {
            let event = match step {
                Step::Status(status) => ParentEvent::Status(status),
                Step::Reconciled {
                    blocks,
                    status,
                    spent,
                    bump_in_flight,
                } => {
                    tip += blocks;
                    ParentEvent::Reconciled {
                        spent_inputs: spent.then(|| input_of(1)).into_iter().collect(),
                        status,
                        tip,
                        rules: RULES,
                        bump_in_flight,
                    }
                }
                Step::Reorged => ParentEvent::Reorged,
                Step::Listener { carried } => {
                    let (listener, receiver) = if carried {
                        carried_listener()
                    } else {
                        never_listener()
                    };
                    receivers.push(receiver);
                    history_added += 1;
                    ParentEvent::JobJoined(listener)
                }
                Step::Bump(outcome) => ParentEvent::BumpFinished {
                    state: BumpState::new("lease"),
                    outcome,
                },
            };
            for action in record.apply(event) {
                match action {
                    ParentAction::Answer(_, result) => answered.push(result),
                    ParentAction::Remove => removed = true,
                    ParentAction::Recover => {}
                }
            }
            if removed {
                break;
            }
        }
        History {
            record,
            added: history_added,
            answered,
            removed,
        }
    }

    fn without_spends(steps: Vec<Step>) -> Vec<Step> {
        steps
            .into_iter()
            .map(|step| match step {
                Step::Reconciled {
                    blocks,
                    status,
                    bump_in_flight,
                    ..
                } => Step::Reconciled {
                    blocks,
                    status,
                    spent: false,
                    bump_in_flight,
                },
                other => other,
            })
            .collect()
    }

    proptest! {
        // No listener is lost: each one is answered or still waits, and a removal leaves none.
        #[test]
        fn every_listener_is_answered_or_waiting(
            steps in prop::collection::vec(arb_step(), 0..40),
            deadline in prop_oneof![Just(DeadlineClass::Deadline), Just(DeadlineClass::NoDeadline)],
        ) {
            let record = test_record(parent(1), Stage::Unconfirmed, deadline);

            let history = run_steps(record, steps);

            prop_assert_eq!(history.answered.len() + history.record.listeners.len(), history.added);
            if history.removed {
                prop_assert!(history.record.listeners.is_empty());
            }
        }

        // A parent ends only through its own burial, a buried conflict, or a failed package for a
        // job that the bare path refused.
        // With no evidence of a spend, nothing reports a conflict.
        #[test]
        fn a_conflict_needs_a_spent_input(steps in prop::collection::vec(arb_step(), 0..40)) {
            let record = test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline);

            let history = run_steps(record, without_spends(steps));

            let conflict = |result: &Result<(), DriveErr>| {
                matches!(result, Err(DriveErr::ConflictBuried))
            };
            prop_assert!(!history.answered.iter().any(conflict));
        }

        // A reconcile with a bump in flight and no evidence that the parent is dead never asks
        // for a removal, so the lease of the bump always has a record to reach.
        #[test]
        fn a_bump_in_flight_blocks_every_removal_short_of_a_final_chain_state(
            steps in prop::collection::vec(arb_step(), 0..40),
            status in prop_oneof![Just(TxStatus::Unknown), Just(TxStatus::Mempool), Just(mined())],
        ) {
            let steps = without_spends(steps);
            let mut history = run_steps(
                test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline),
                steps,
            );
            prop_assume!(!history.removed);

            let actions = history.record.apply(ParentEvent::Reconciled {
                spent_inputs: BTreeSet::new(),
                status,
                tip: 10_000,
                rules: RULES,
                bump_in_flight: true,
            });

            prop_assert!(!removes(&actions));
        }

    }

    /// A ZMQ event and a reconcile move a fresh record the same way.
    #[test]
    fn both_routes_set_the_same_stage_for_each_status() {
        for status in [TxStatus::Unknown, TxStatus::Mempool, mined(), buried()] {
            for via_reconcile in [false, true] {
                let mut record =
                    test_record(parent(1), Stage::Unconfirmed, DeadlineClass::Deadline);
                let event = if via_reconcile {
                    reconciled(100, status.clone(), &[])
                } else {
                    ParentEvent::Status(status.clone())
                };

                let actions = record.apply(event);

                assert_eq!(removes(&actions), status.is_buried(), "status = {status}");
                assert_eq!(
                    record.stage == Stage::Mined,
                    status.is_mined(),
                    "status = {status}"
                );
            }
        }
    }
}

/// Tests of the steps that a bump task runs.
#[cfg(test)]
mod bump_tests {
    use super::{test_support::*, *};

    fn core_with(bumper: Arc<dyn CpfpBumper>, records: Vec<ParentRecord>) -> DriverCore {
        let bumper = Some(bumper);
        let map = records
            .into_iter()
            .map(|record| (record.tx.compute_txid(), record))
            .collect();
        DriverCore {
            chain: Arc::new(FakeChain::default()),
            bumper,
            parents: Arc::new(Mutex::new(map)),
            rules: RULES,
        }
    }

    fn unconfirmed_record() -> ParentRecord {
        test_record(parent(1), Stage::Unconfirmed, DeadlineClass::NoDeadline)
    }

    async fn mark_of(core: &DriverCore, txid: Txid) -> Arc<AtomicBool> {
        let map = core.parents.lock().await;
        Arc::clone(&map[&txid].cpfp.as_ref().expect("cpfp state").bumping)
    }

    /// A record that one failed broadcast waits on.
    fn carrying(listener: Listener) -> ParentRecord {
        let mut record = unconfirmed_record();
        record.listeners.push(listener);
        record
    }

    fn broadcasts(chain: &FakeChain) -> usize {
        chain.broadcasts.load(Ordering::SeqCst)
    }

    /// A core over `record` with `outcome`, and the chain that counts its broadcasts.
    fn core_with_chain(outcome: BumpOutcome, record: ParentRecord) -> (DriverCore, Arc<FakeChain>) {
        let chain = Arc::new(FakeChain::default());
        let mut core = core_with(Arc::new(FakeBumper::reporting(outcome)), vec![record]);
        core.chain = chain.clone();
        (core, chain)
    }

    /// A mined parent is not bumped: a confirmed parent needs no child. The same record at
    /// `Unconfirmed` bumps, so the stage is the only difference under test.
    #[tokio::test]
    async fn bump_parent_skips_mined_parents() {
        let txid = parent(1).compute_txid();

        for (stage, expected_calls) in [(Stage::Mined, 0), (Stage::Unconfirmed, 1)] {
            let bumper = Arc::new(FakeBumper::reporting(BumpOutcome::Submitted));
            let record = test_record(parent(1), stage, DeadlineClass::NoDeadline);
            let core = core_with(bumper.clone(), vec![record]);
            let mark = mark_of(&core, txid).await;

            core.bump_parent(txid, &mark).await;

            assert_eq!(bumper.calls(), expected_calls, "stage = {stage:?}");
        }
    }

    /// Even a bump that lands no package must land its state back in the record. The bumper
    /// stores the lease on the new child's funding inputs before the steps that can fail,
    /// and the next bump can only reuse those inputs if that update survives into the record.
    #[tokio::test]
    async fn bump_parent_writes_the_state_back_when_no_package_lands() {
        let txid = parent(1).compute_txid();
        let bumper = Arc::new(FakeBumper::storing(BumpOutcome::NoPackage, "lease"));
        let core = core_with(bumper, vec![unconfirmed_record()]);
        let mark = mark_of(&core, txid).await;

        core.bump_parent(txid, &mark).await;

        let map = core.parents.lock().await;
        let cpfp = map[&txid].cpfp.as_ref().expect("cpfp state");
        assert_eq!(cpfp.state.get::<&str>(), Some(&"lease"));
    }

    /// A vanished record (parent buried between look-up and bump) is a quiet no-op: in
    /// particular the bumper must never be asked to fund a child for it.
    #[tokio::test]
    async fn bump_parent_is_noop_when_the_record_vanished() {
        let bumper = Arc::new(FakeBumper::reporting(BumpOutcome::Submitted));
        let core = core_with(bumper.clone(), Vec::new());

        let outcome = core
            .bump_parent(parent(1).compute_txid(), &Arc::new(AtomicBool::new(true)))
            .await;

        assert_eq!(outcome, None);
        assert_eq!(bumper.calls(), 0);
    }

    /// The eviction path puts a parent back bare only when no package went out.
    #[tokio::test]
    async fn an_eviction_resubmits_bare_only_when_no_package_goes_out() {
        let txid = parent(1).compute_txid();
        for (outcome, expected) in [
            (BumpOutcome::NoPackage, 1),
            (BumpOutcome::Submitted, 0),
            (BumpOutcome::ParentIsLive, 0),
        ] {
            let (core, chain) = core_with_chain(outcome, unconfirmed_record());

            core.bump_once(txid, BumpFollowUp::ResubmitBare(None)).await;

            assert_eq!(broadcasts(&chain), expected, "outcome = {outcome:?}");
        }
    }

    /// An evicted parent goes back into the mempool when another trigger holds the mark.
    #[tokio::test]
    async fn an_eviction_with_no_bump_to_run_still_resubmits_bare() {
        let txid = parent(1).compute_txid();
        let (core, chain) = core_with_chain(BumpOutcome::Submitted, unconfirmed_record());
        let _held = core.take_bump_mark(txid).await;

        core.bump_once(txid, BumpFollowUp::ResubmitBare(None)).await;

        assert_eq!(broadcasts(&chain), 1);
    }

    /// A parent with no CPFP takes the same call, and it goes back bare.
    #[tokio::test]
    async fn an_eviction_of_a_parent_with_no_cpfp_resubmits_bare() {
        let txid = parent(1).compute_txid();
        let mut record = unconfirmed_record();
        record.cpfp = None;
        let (core, chain) = core_with_chain(BumpOutcome::Submitted, record);

        core.bump_once(txid, BumpFollowUp::ResubmitBare(None)).await;

        assert_eq!(broadcasts(&chain), 1);
    }

    /// A removed parent has no job that wants it back.
    #[tokio::test]
    async fn a_resubmission_of_a_removed_parent_sends_nothing() {
        let txid = parent(1).compute_txid();
        let (core, chain) = core_with_chain(BumpOutcome::Submitted, unconfirmed_record());
        core.parents.lock().await.clear();

        core.resubmit_bare(txid, None).await;

        assert_eq!(broadcasts(&chain), 0);
    }

    /// The package fallback is the last chance for a parent that bare broadcast rejected. When it
    /// fails too, the caller hears the broadcast error rather than wait forever, and the record
    /// stays at `Expired` until a reconcile reads the parent in no mempool.
    #[tokio::test]
    async fn a_failed_package_fallback_expires_the_record_and_reports_the_error() {
        let txid = parent(1).compute_txid();
        let bumper = Arc::new(FakeBumper::reporting(BumpOutcome::NoPackage));
        let (listener, receiver) = carried_listener();
        let core = core_with(bumper, vec![carrying(listener)]);

        core.bump_once(txid, BumpFollowUp::Wait).await;

        assert_eq!(
            core.parents.lock().await.get(&txid).map(|r| r.stage),
            Some(Stage::Expired)
        );
        assert!(matches!(
            receiver.await,
            Ok(Err(DriveErr::PublishFailed(_)))
        ));
    }

    /// A second failed broadcast during a bump hears the result of that bump, with no second
    /// attempt, and the bump that holds the mark can still land its parent.
    #[tokio::test]
    async fn a_carried_job_that_joins_during_a_bump_hears_that_bump() {
        let txid = parent(1).compute_txid();
        let (bumper, gate) = FakeBumper::gated(BumpOutcome::NoPackage, "lease");
        let bumper = Arc::new(bumper);
        let (first, first_receiver) = carried_listener();
        let core = core_with(bumper.clone(), vec![carrying(first)]);
        let task = bump_in_flight(&core, &bumper, txid).await;
        let (second, second_receiver) = carried_listener();

        apply_event(
            &mut *core.parents.lock().await,
            txid,
            ParentEvent::JobJoined(second),
        );
        core.bump_once(txid, BumpFollowUp::Wait).await;
        assert_eq!(bumper.calls(), 1, "the mark stops a second attempt");
        gate.add_permits(1);
        task.await.expect("the bump task must not panic");

        assert_eq!(
            core.parents.lock().await.get(&txid).map(|r| r.stage),
            Some(Stage::Expired)
        );
        for receiver in [first_receiver, second_receiver] {
            assert!(matches!(
                receiver.await,
                Ok(Err(DriveErr::PublishFailed(_)))
            ));
        }
    }

    /// An unbumpable parent that entered through a failed bare broadcast must go completely.
    /// The package was its only route into a mempool, so its record is removed, and its caller
    /// hears the broadcast error.
    #[tokio::test]
    async fn an_unbumpable_carried_job_still_removes_its_record() {
        let txid = parent(1).compute_txid();
        let bumper = Arc::new(FakeBumper::reporting(BumpOutcome::Unbumpable));
        let (listener, receiver) = carried_listener();
        let core = core_with(bumper, vec![carrying(listener)]);

        core.bump_once(txid, BumpFollowUp::Wait).await;

        assert!(core.parents.lock().await.is_empty());
        assert!(matches!(
            receiver.await,
            Ok(Err(DriveErr::PublishFailed(_)))
        ));
    }

    /// A bump that took its mark on a removed record must not touch a newer record of the
    /// same txid.
    #[tokio::test]
    async fn a_bump_of_a_removed_record_leaves_a_newer_record_alone() {
        let txid = parent(1).compute_txid();
        let bumper = Arc::new(FakeBumper::reporting(BumpOutcome::Unbumpable));
        let core = core_with(bumper.clone(), vec![unconfirmed_record()]);
        let stale = mark_of(&core, txid).await;
        core.parents.lock().await.insert(txid, unconfirmed_record());

        let outcome = core.bump_parent(txid, &stale).await;

        assert_eq!(outcome, None);
        assert_eq!(bumper.calls(), 0);
        assert!(core.parents.lock().await[&txid].is_bumpable());
    }

    /// A gated bump of the one record of `core`, stopped inside the bumper.
    async fn bump_in_flight(core: &DriverCore, bumper: &FakeBumper, txid: Txid) -> JoinHandle<()> {
        let task = tokio::spawn({
            let core = core.clone();
            async move { core.bump_once(txid, BumpFollowUp::Wait).await }
        });
        while bumper.calls() == 0 {
            tokio::task::yield_now().await;
        }
        task
    }

    fn lease_of(core_map: &ParentMap, txid: &Txid) -> Option<&'static str> {
        let cpfp = core_map[txid].cpfp.as_ref().expect("cpfp state");
        cpfp.state.get::<&str>().copied()
    }

    /// A bump that ends after its record went writes nothing, and it leaves a newer record of
    /// the same txid alone.
    #[tokio::test]
    async fn a_bump_that_ends_after_a_removal_leaves_a_newer_record_alone() {
        let txid = parent(1).compute_txid();
        let (bumper, gate) = FakeBumper::gated(BumpOutcome::Submitted, "lease");
        let bumper = Arc::new(bumper);
        let core = core_with(bumper.clone(), vec![unconfirmed_record()]);
        let task = bump_in_flight(&core, &bumper, txid).await;

        core.parents.lock().await.insert(txid, unconfirmed_record());
        gate.add_permits(1);
        task.await.expect("the bump task must not panic");

        assert_eq!(lease_of(&*core.parents.lock().await, &txid), None);
    }

    /// A parent that reaches a block during a bump keeps the lease of the child of that bump,
    /// because the child can be live.
    #[tokio::test]
    async fn a_bump_that_ends_after_the_parent_mined_keeps_its_lease() {
        let txid = parent(1).compute_txid();
        let (bumper, gate) = FakeBumper::gated(BumpOutcome::Submitted, "lease");
        let bumper = Arc::new(bumper);
        let core = core_with(bumper.clone(), vec![unconfirmed_record()]);
        let task = bump_in_flight(&core, &bumper, txid).await;

        apply_event(
            &mut *core.parents.lock().await,
            txid,
            ParentEvent::Status(mined()),
        );
        gate.add_permits(1);
        task.await.expect("the bump task must not panic");

        let map = core.parents.lock().await;
        assert_eq!(map[&txid].stage, Stage::Mined);
        assert_eq!(lease_of(&map, &txid), Some("lease"));
    }

    /// A job whose record went during its read inserts a new record with its own subscription.
    #[tokio::test]
    async fn a_job_whose_record_went_opens_its_subscription_at_the_insert() {
        let tx = parent(1);
        let txid = tx.compute_txid();
        let (core, chain) = core_with_chain(BumpOutcome::Submitted, unconfirmed_record());
        core.parents.lock().await.clear();
        let (listener, _receiver) = never_listener();
        let mut active_tx_subs = ActiveSubscriptions::new();

        core.track(
            tx,
            Stage::Unconfirmed,
            None,
            listener,
            None,
            &mut active_tx_subs,
        )
        .await;

        assert_eq!(chain.subscriptions.load(Ordering::SeqCst), 1);
        assert_eq!(active_tx_subs.len(), 1);
        assert!(core.parents.lock().await.contains_key(&txid));
    }

    /// The per-parent mark stops a second trigger from bumping a parent whose bump is still
    /// running. Two concurrent bumps snapshot one state, and the later write-back drops the
    /// lease that the earlier one took.
    #[tokio::test]
    async fn a_second_trigger_does_not_bump_a_parent_that_is_already_bumping() {
        let txid = parent(1).compute_txid();
        let bumper = Arc::new(FakeBumper::reporting(BumpOutcome::Submitted));
        let core = core_with(bumper, vec![unconfirmed_record()]);

        let held = core.take_bump_mark(txid).await;

        assert!(held.is_some());
        assert!(core.take_bump_mark(txid).await.is_none());
    }

    /// The mark clears when the bump ends, so the next trigger can bump again.
    #[tokio::test]
    async fn the_bump_mark_clears_when_the_bump_ends() {
        let txid = parent(1).compute_txid();
        let bumper = Arc::new(FakeBumper::reporting(BumpOutcome::Submitted));
        let core = core_with(bumper, vec![unconfirmed_record()]);

        core.bump_once(txid, BumpFollowUp::Wait).await;

        assert!(core.take_bump_mark(txid).await.is_some());
    }
}

/// Tests that run the real select loop with a fake node and a fake bumper.
#[cfg(test)]
mod loop_tests {
    use bitcoin::{hashes::Hash, BlockHash, CompactTarget, TxMerkleNode};
    use tokio::time::{sleep, timeout};

    use super::{test_support::*, *};

    /// A running driver and the handles that a test scripts it through.
    struct Harness {
        driver: Arc<TxDriver>,
        chain: Arc<FakeChain>,
        bumper: Arc<FakeBumper>,
        blocks: UnboundedSender<BlockEvent>,
    }

    /// No tick fires in the test time of this harness. Blocks are the only trigger.
    fn harness(outcome: BumpOutcome) -> Harness {
        harness_with_interval(outcome, Duration::from_secs(3600))
    }

    fn harness_with_interval(outcome: BumpOutcome, bump_check_interval: Duration) -> Harness {
        let chain = Arc::new(FakeChain::default());
        let bumper = Arc::new(FakeBumper::reporting(outcome));
        let (blocks, block_receiver) = unbounded_channel();
        let driver = TxDriver::spawn(
            chain.clone(),
            Subscription::from_receiver(block_receiver),
            Some((bumper.clone(), bump_check_interval)),
            RULES,
        );
        Harness {
            driver: Arc::new(driver),
            chain,
            bumper,
            blocks,
        }
    }

    impl Harness {
        /// Connects a block at height `tip` and waits until the driver has handled it.
        async fn connect_block(&self, tip: u64) {
            self.chain.set_tip(tip);
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
        /// condition that must become true uses [`Self::wait_for_bumps`] instead.
        async fn settle(&self) {
            sleep(Duration::from_millis(20)).await;
        }

        async fn wait_for_bumps(&self, calls: usize) {
            timeout(Duration::from_secs(5), async {
                while self.bumper.calls() < calls {
                    sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the bumps must run");
        }

        /// Drives `tx` from a spawned task, so that the test can script events during the wait.
        fn drive_with_cpfp(
            &self,
            tx: &Transaction,
            deadline: DeadlineClass,
            condition: fn(&TxStatus) -> bool,
        ) -> JoinHandle<Result<(), DriveErr>> {
            let driver = self.driver.clone();
            let tx = tx.clone();
            let strategy = strategy(&tx, deadline);
            tokio::spawn(async move { driver.drive_with_cpfp(tx, strategy, condition).await })
        }
    }

    async fn outcome_of(task: JoinHandle<Result<(), DriveErr>>) -> Result<(), DriveErr> {
        timeout(Duration::from_secs(5), task)
            .await
            .expect("the caller must hear an answer")
            .expect("the drive task must not panic")
    }

    /// With ZMQ silent, the reconcile alone moves a parent through its whole life.
    #[tokio::test]
    async fn a_reconcile_ends_a_record_with_no_zmq_event() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let txid = tx.compute_txid();
        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;

        harness.connect_block(100).await;
        harness.wait_for_bumps(2).await;

        harness.chain.set_status(txid, mined());
        harness.connect_block(101).await;
        harness.connect_block(102).await;
        assert_eq!(harness.bumper.calls(), 2, "a mined parent takes no bump");

        harness.chain.set_status(txid, buried());
        harness.connect_block(107).await;
        outcome_of(drive)
            .await
            .expect("the caller hears the burial");
    }

    /// ZMQ events keep driving the record: an event for a variant with another witness counts,
    /// and an eviction puts the parent back through a bump.
    #[tokio::test]
    async fn zmq_events_drive_the_record_for_any_witness() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let mut variant = tx.clone();
        variant.input[0].witness.push([7]);
        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;

        harness.chain.emit(&variant, TxStatus::Unknown);
        harness.wait_for_bumps(2).await;

        harness.chain.emit(&variant, mined());
        harness.settle().await;
        harness.chain.emit(&variant, TxStatus::Unknown);
        harness.wait_for_bumps(3).await;

        harness.chain.emit(&variant, buried());
        outcome_of(drive)
            .await
            .expect("the caller hears the burial");
    }

    /// A failed read of the node does not fail the job: the transaction goes to the broadcast,
    /// and the node decides.
    #[tokio::test]
    async fn a_failed_read_falls_through_to_the_broadcast() {
        let harness = harness(BumpOutcome::Submitted);
        harness.chain.rpc_down.store(true, Ordering::SeqCst);
        let tx = parent(1);

        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.settle().await;

        assert_eq!(harness.chain.broadcasts.load(Ordering::SeqCst), 1);
        assert!(
            !drive.is_finished(),
            "the job waits on the broadcast transaction"
        );
    }

    /// A status read that fails must not count as an eviction.
    #[tokio::test]
    async fn a_failed_read_leaves_the_record_as_it_is() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let txid = tx.compute_txid();
        harness.chain.set_status(txid, mined());
        let _drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.settle().await;
        harness.chain.rpc_down.store(true, Ordering::SeqCst);
        let broadcasts = harness.chain.broadcasts.load(Ordering::SeqCst);

        harness.connect_block(100).await;

        assert_eq!(harness.chain.broadcasts.load(Ordering::SeqCst), broadcasts);
        assert_eq!(harness.bumper.calls(), 0, "the record stays at Mined");
    }

    /// A parent that the node reports as mined starts at `Mined`, so it takes no bump, on the
    /// job or on later blocks.
    #[tokio::test]
    async fn a_job_for_a_mined_parent_takes_no_bump() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let txid = tx.compute_txid();
        harness.chain.set_status(txid, mined());

        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.settle().await;
        harness.connect_block(100).await;
        harness.connect_block(101).await;

        assert_eq!(harness.bumper.calls(), 0);
        harness.chain.set_status(txid, buried());
        harness.connect_block(102).await;
        outcome_of(drive)
            .await
            .expect("the caller hears the burial");
    }

    /// A parent that its caller priced at the market rate takes no bump at the publish. The
    /// first block trigger bumps it.
    #[tokio::test]
    async fn a_parent_priced_at_the_publish_waits_for_a_trigger() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let mut strategy = strategy(&tx, DeadlineClass::NoDeadline);
        strategy.first_bump = FirstBump::AtTrigger;
        let driver = harness.driver.clone();
        let _drive = tokio::spawn(async move {
            driver
                .drive_with_cpfp(tx, strategy, TxStatus::is_buried)
                .await
        });
        harness.settle().await;
        assert_eq!(harness.bumper.calls(), 0, "no bump at the publish");

        harness.connect_block(100).await;
        harness.wait_for_bumps(1).await;
    }

    /// A buried parent can never meet a condition that its status does not meet. The caller
    /// hears that at once, and the driver tracks nothing.
    #[tokio::test]
    async fn a_job_for_a_buried_parent_that_misses_its_condition_fails_at_once() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        harness.chain.set_status(tx.compute_txid(), buried());

        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, |_| false);

        assert!(matches!(
            outcome_of(drive).await,
            Err(DriveErr::ConditionUnmet)
        ));
        assert_eq!(harness.bumper.calls(), 0);
    }

    /// A retry job that finds the parent buried ends the record, and the first caller of a
    /// record that ZMQ never ended hears the result too.
    #[tokio::test]
    async fn a_job_that_reads_burial_ends_the_existing_record() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let txid = tx.compute_txid();
        let first = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, |_| false);
        harness.wait_for_bumps(1).await;

        harness.chain.set_status(txid, buried());
        let retry = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);

        outcome_of(retry).await.expect("the retry reads burial");
        assert!(matches!(
            outcome_of(first).await,
            Err(DriveErr::ConditionUnmet)
        ));
    }

    /// A bare broadcast that fails is carried by a package, and the caller of a package that
    /// lands stays in the record.
    #[tokio::test]
    async fn a_rejected_broadcast_is_carried_by_a_package() {
        let harness = harness(BumpOutcome::Submitted);
        harness.chain.reject_broadcast.store(true, Ordering::SeqCst);
        let tx = parent(1);
        let txid = tx.compute_txid();

        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;
        harness.settle().await;
        assert!(!drive.is_finished(), "the caller waits on the record");

        harness.chain.set_status(txid, buried());
        harness.connect_block(100).await;
        outcome_of(drive)
            .await
            .expect("the caller hears the burial");
    }

    /// A spent input means that no child can enter a mempool, so a failed broadcast ends the job
    /// with no bump.
    #[tokio::test]
    async fn a_rejected_broadcast_with_a_spent_input_takes_no_bump() {
        let harness = harness(BumpOutcome::Submitted);
        harness.chain.reject_broadcast.store(true, Ordering::SeqCst);
        harness
            .chain
            .spent
            .lock()
            .expect("not poisoned")
            .insert(input_of(1));

        let drive =
            harness.drive_with_cpfp(&parent(1), DeadlineClass::Deadline, TxStatus::is_buried);

        assert!(matches!(
            outcome_of(drive).await,
            Err(DriveErr::PublishFailed(_))
        ));
        harness.settle().await;
        assert_eq!(harness.bumper.calls(), 0);
    }

    /// A buried conflict on an input ends a deadline parent, and the bumps end with it.
    #[tokio::test]
    async fn a_buried_conflict_stops_a_parent_through_the_loop() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;

        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Unknown);
        harness
            .chain
            .spent
            .lock()
            .expect("not poisoned")
            .insert(input_of(1));
        harness.connect_block(100).await;
        harness.connect_block(105).await;
        assert!(!drive.is_finished(), "the conflict is not buried yet");

        harness.connect_block(106).await;
        assert!(matches!(
            outcome_of(drive).await,
            Err(DriveErr::ConflictBuried)
        ));
        let calls = harness.bumper.calls();
        harness.connect_block(107).await;
        assert_eq!(
            harness.bumper.calls(),
            calls,
            "the bumps end with the record"
        );
    }

    /// A block that connects between the spend read and the tip read must not shorten the
    /// burial of the conflict.
    #[tokio::test]
    async fn a_block_during_a_reconcile_does_not_shorten_a_conflict_burial() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;
        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Unknown);
        harness
            .chain
            .spent
            .lock()
            .expect("not poisoned")
            .insert(input_of(1));

        // The spender is in block 101, and the pass that sees it started at tip 100.
        *harness
            .chain
            .tip_during_spend_read
            .lock()
            .expect("not poisoned") = Some(101);
        harness.connect_block(100).await;
        *harness
            .chain
            .tip_during_spend_read
            .lock()
            .expect("not poisoned") = None;

        harness.connect_block(106).await;
        assert!(!drive.is_finished(), "block 101 has five blocks on top");

        harness.connect_block(107).await;
        assert!(matches!(
            outcome_of(drive).await,
            Err(DriveErr::ConflictBuried)
        ));
    }

    /// A duplicate job finds the record, so it opens no second subscription.
    #[tokio::test]
    async fn a_duplicate_job_opens_no_subscription() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let _first = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;

        let _second = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(2).await;

        assert_eq!(harness.chain.subscriptions.load(Ordering::SeqCst), 1);
    }

    /// A `Buried` block event is the second half of one connect, so it runs no second walk.
    #[tokio::test]
    async fn a_buried_block_event_runs_no_walk() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let _drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;

        harness.send_block(BlockStatus::Buried);
        harness.settle().await;

        assert_eq!(harness.bumper.calls(), 1);
    }

    /// A block that leaves the chain restarts the burial of a seen conflict, also when the
    /// output reads as spent the whole time.
    #[tokio::test]
    async fn a_disconnected_block_restarts_the_burial_of_a_conflict() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;
        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Unknown);
        harness
            .chain
            .spent
            .lock()
            .expect("not poisoned")
            .insert(input_of(1));
        harness.connect_block(100).await;

        harness.chain.set_tip(104);
        harness.send_block(BlockStatus::Uncled);
        harness.settle().await;
        harness.connect_block(106).await;
        assert!(!drive.is_finished(), "the spender has two blocks on top");

        harness.connect_block(110).await;
        assert!(matches!(
            outcome_of(drive).await,
            Err(DriveErr::ConflictBuried)
        ));
    }

    /// A read that fails during the reorg pass must not lose the restart of the burial.
    #[tokio::test]
    async fn a_failed_read_on_a_disconnected_block_still_restarts_the_burial() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        let drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;
        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Unknown);
        harness
            .chain
            .spent
            .lock()
            .expect("not poisoned")
            .insert(input_of(1));
        harness.connect_block(100).await;

        harness.chain.rpc_down.store(true, Ordering::SeqCst);
        harness.chain.set_tip(104);
        harness.send_block(BlockStatus::Uncled);
        harness.settle().await;
        harness.chain.rpc_down.store(false, Ordering::SeqCst);

        harness.connect_block(106).await;
        assert!(!drive.is_finished(), "the spender has two blocks on top");
    }

    /// A block that leaves the chain reconciles the record, so a parent that it held bumps again
    /// with no ZMQ event.
    #[tokio::test]
    async fn a_disconnected_block_wakes_a_mined_parent() {
        let harness = harness(BumpOutcome::Submitted);
        let tx = parent(1);
        harness.chain.set_status(tx.compute_txid(), mined());
        let _drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.settle().await;
        assert_eq!(harness.bumper.calls(), 0);

        harness
            .chain
            .set_status(tx.compute_txid(), TxStatus::Mempool);
        harness.send_block(BlockStatus::Uncled);

        harness.wait_for_bumps(1).await;
    }

    /// The tick walks every parent with no block, which is what revives an evicted child.
    #[tokio::test]
    async fn a_tick_bumps_a_parent_with_no_block() {
        let harness = harness_with_interval(BumpOutcome::Submitted, Duration::from_millis(5));
        let tx = parent(1);
        let _drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);

        harness.wait_for_bumps(3).await;
    }

    /// A walk bumps a CPFP parent that left the mempool, and a declined bump puts it back bare.
    #[tokio::test]
    async fn a_walk_resubmits_a_parent_whose_bump_sent_no_package() {
        let harness = harness(BumpOutcome::NoPackage);
        let tx = parent(1);
        let txid = tx.compute_txid();
        let _drive = harness.drive_with_cpfp(&tx, DeadlineClass::Deadline, TxStatus::is_buried);
        harness.wait_for_bumps(1).await;
        harness.settle().await;
        assert_eq!(harness.chain.broadcasts.load(Ordering::SeqCst), 1);

        harness.chain.set_status(txid, TxStatus::Unknown);
        harness.connect_block(100).await;
        harness.wait_for_bumps(2).await;
        harness.settle().await;

        assert_eq!(harness.chain.broadcasts.load(Ordering::SeqCst), 2);
    }
}

/// Tests of the RPC reads against a regtest node. These need no ZMQ, so they run in parallel.
#[cfg(test)]
mod rpc_tests {
    use bitcoin::Address;
    use corepc_node::{Conf, Node, Output};

    use super::*;

    fn setup() -> (Node, BitcoinClient, Address) {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let node = Node::with_conf("bitcoind", &conf).expect("bitcoind must start");
        let cookie = node
            .params
            .get_cookie_values()
            .expect("can read cookie")
            .expect("can parse cookie");
        let auth = bitcoind_async_client::Auth::UserPass(cookie.user, cookie.password);
        let client = BitcoinClient::new(node.rpc_url(), auth, None, None, None)
            .expect("can set up rpc client");
        let address = node.client.new_address().expect("wallet address");
        node.client
            .generate_to_address(101, &address)
            .expect("coinbase matures");
        (node, client, address)
    }

    /// Sends one payment and returns the outpoint of the first output of the mempool transaction.
    fn send(node: &Node, address: &Address) -> OutPoint {
        let txid = node
            .client
            .send_to_address(address, Amount::from_btc(1.0).expect("valid amount"))
            .expect("the wallet is funded")
            .txid()
            .expect("valid txid");
        OutPoint { txid, vout: 0 }
    }

    /// Spends every wallet output, so that the outputs of `outpoint.txid` go too.
    fn spend_all(node: &Node, address: &Address) {
        let balance = node
            .client
            .get_balance()
            .expect("wallet balance")
            .balance()
            .expect("valid balance");
        let out = Output::new(
            address.clone(),
            balance - Amount::from_btc(0.01).expect("fee"),
        );
        let raw = node
            .client
            .create_raw_transaction(&[], &[out])
            .expect("raw transaction")
            .0;
        let funded: corepc_node::vtype::FundRawTransaction = node
            .client
            .call("fundrawtransaction", &[raw.into()])
            .expect("funded");
        let tx = funded.into_model().expect("valid transaction").tx;
        let signed = node
            .client
            .sign_raw_transaction_with_wallet(&tx)
            .expect("signed")
            .into_model()
            .expect("valid transaction")
            .tx;
        node.client.send_raw_transaction(&signed).expect("accepted");
    }

    /// An output of a transaction in the mempool has no UTXO entry, and that is no spend.
    #[tokio::test]
    async fn an_output_of_a_mempool_transaction_reads_as_not_spent() {
        let (node, client, address) = setup();
        let outpoint = send(&node, &address);

        assert!(!read_spent_on_chain(&client, outpoint).await.expect("read"));
    }

    #[tokio::test]
    async fn an_unspent_confirmed_output_reads_as_not_spent() {
        let (node, client, address) = setup();
        let outpoint = send(&node, &address);
        node.client
            .generate_to_address(1, &address)
            .expect("block mines");

        assert!(!read_spent_on_chain(&client, outpoint).await.expect("read"));
    }

    #[tokio::test]
    async fn only_a_confirmed_spend_reads_as_spent() {
        let (node, client, address) = setup();
        let outpoint = send(&node, &address);
        node.client
            .generate_to_address(1, &address)
            .expect("block mines");
        spend_all(&node, &address);
        assert!(
            !read_spent_on_chain(&client, outpoint).await.expect("read"),
            "a mempool spend is not a confirmed spend"
        );

        node.client
            .generate_to_address(1, &address)
            .expect("block mines");

        assert!(read_spent_on_chain(&client, outpoint).await.expect("read"));
    }

    /// `txindex` keeps the entry of a block that left the chain. A transaction in that block reads
    /// as in the mempool, also once a replacement has taken its place there.
    #[tokio::test]
    async fn a_transaction_of_a_disconnected_block_reads_as_in_the_mempool() {
        let (node, client, address) = setup();
        let txid = send(&node, &address).txid;
        let blocks = node
            .client
            .generate_to_address(1, &address)
            .expect("block mines")
            .into_model()
            .expect("valid hashes");
        let block = blocks.0[0].to_string();
        let _: serde::de::IgnoredAny = node
            .client
            .call("invalidateblock", &[block.into()])
            .expect("block disconnects");
        assert_eq!(
            read_status(&client, txid, 2).await.expect("read"),
            TxStatus::Mempool,
            "a disconnect returns the transaction to the mempool"
        );

        let _: serde::de::IgnoredAny = node
            .client
            .call("bumpfee", &[txid.to_string().into()])
            .expect("the replacement takes the mempool");

        assert_eq!(
            read_status(&client, txid, 2).await.expect("read"),
            TxStatus::Mempool
        );
    }

    #[tokio::test]
    async fn read_status_follows_a_transaction_to_burial() {
        let (node, client, address) = setup();
        let txid = send(&node, &address).txid;
        let unknown = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        assert_eq!(
            read_status(&client, unknown, 2).await.expect("read"),
            TxStatus::Unknown
        );
        assert_eq!(
            read_status(&client, txid, 2).await.expect("read"),
            TxStatus::Mempool
        );

        node.client
            .generate_to_address(1, &address)
            .expect("block mines");
        let status = read_status(&client, txid, 2).await.expect("read");
        assert!(
            status.is_mined(),
            "one confirmation is below the bury depth"
        );
        let height = client.get_block_count().await.expect("tip");
        assert!(matches!(status, TxStatus::Mined { height: h, .. } if h == height));

        node.client
            .generate_to_address(1, &address)
            .expect("block mines");
        assert!(read_status(&client, txid, 2)
            .await
            .expect("read")
            .is_buried());
    }
}
