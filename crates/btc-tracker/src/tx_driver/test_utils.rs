//! Test doubles that the driver test modules share.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use bitcoin::{
    absolute, hashes::Hash, transaction::Version, Amount, BlockHash, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoind_async_client::error::ClientError;
use strata_bridge_primitives::{cpfp::ChildSpend, subscription::Subscription};
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedSender},
    Semaphore,
};

use super::node::ChainAccess;
use crate::{
    cpfp::{BumpOutcome, CpfpBumper, CpfpStrategy, DeadlineClass, FirstBump},
    event::{TxEvent, TxStatus},
};

/// The bury depth of every test.
pub(super) const BURY_DEPTH: u64 = 6;

/// A bumper that reports a set outcome and records each parent it bumps.
///
/// Each bump stores a clone of one shared token as the parent's state, so a test reads how many
/// states, and with them leases, are still held. With a gate, each bump waits for one permit.
#[derive(Debug)]
pub(super) struct FakeBumper {
    outcome: Mutex<BumpOutcome>,
    gate: Option<Arc<Semaphore>>,
    calls: AtomicUsize,
    bumped: Mutex<Vec<Txid>>,
    saw_state: Mutex<Vec<bool>>,
    lease: Arc<()>,
}

impl FakeBumper {
    pub(super) fn reporting(outcome: BumpOutcome) -> Self {
        Self {
            outcome: Mutex::new(outcome),
            gate: None,
            calls: AtomicUsize::new(0),
            bumped: Mutex::new(Vec::new()),
            saw_state: Mutex::new(Vec::new()),
            lease: Arc::new(()),
        }
    }

    /// A bumper whose gate starts closed.
    pub(super) fn gated(outcome: BumpOutcome) -> (Self, Arc<Semaphore>) {
        let gate = Arc::new(Semaphore::new(0));
        let bumper = Self {
            gate: Some(gate.clone()),
            ..Self::reporting(outcome)
        };
        (bumper, gate)
    }

    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The parents in the order that their bumps started.
    pub(super) fn bumped(&self) -> Vec<Txid> {
        self.bumped.lock().expect("not poisoned").clone()
    }

    /// For each bump, whether it found the state of an earlier bump.
    pub(super) fn saw_state(&self) -> Vec<bool> {
        self.saw_state.lock().expect("not poisoned").clone()
    }

    /// How many bump states hold the token.
    pub(super) fn leases_held(&self) -> usize {
        Arc::strong_count(&self.lease) - 1
    }
}

#[async_trait]
impl CpfpBumper for FakeBumper {
    /// The token while a bump has run.
    type State = Option<Arc<()>>;

    async fn bump(
        &self,
        parent: &Transaction,
        _strategy: &CpfpStrategy,
        state: &mut Self::State,
    ) -> BumpOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bumped
            .lock()
            .expect("not poisoned")
            .push(parent.compute_txid());
        self.saw_state
            .lock()
            .expect("not poisoned")
            .push(state.is_some());
        *state = Some(self.lease.clone());
        if let Some(gate) = &self.gate {
            gate.acquire().await.expect("the gate stays open").forget();
        }
        *self.outcome.lock().expect("not poisoned")
    }
}

/// The node that a test scripts: statuses, on-chain spends, the tip, and open subscriptions.
#[derive(Default)]
pub(super) struct FakeChain {
    pub(super) statuses: Mutex<HashMap<Txid, TxStatus>>,
    pub(super) spent: Mutex<BTreeSet<OutPoint>>,
    pub(super) tip: Mutex<u64>,
    /// Rejects every send while set. A send whose input is spent is rejected regardless.
    pub(super) reject_broadcast: AtomicBool,
    pub(super) broadcasts: AtomicUsize,
    pub(super) subscribers: Mutex<HashMap<Txid, UnboundedSender<TxEvent>>>,
    pub(super) subscriptions: AtomicUsize,
    /// Fails every read while set.
    pub(super) rpc_down: AtomicBool,
    /// Moves the tip during a spend read, as a block that connects between two reads does.
    pub(super) tip_during_spend_read: Mutex<Option<u64>>,
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

    pub(super) fn spend(&self, outpoint: OutPoint) {
        self.spent.lock().expect("not poisoned").insert(outpoint);
    }

    pub(super) fn broadcasts(&self) -> usize {
        self.broadcasts.load(Ordering::SeqCst)
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
        if self.rpc_down.load(Ordering::SeqCst) {
            return Err(ClientError::Other("connection refused".into()));
        }
        if let Some(tip) = *self.tip_during_spend_read.lock().expect("not poisoned") {
            self.set_tip(tip);
        }
        Ok(self.spent.lock().expect("not poisoned").contains(&outpoint))
    }

    async fn tip_height(&self) -> Result<u64, ClientError> {
        if self.rpc_down.load(Ordering::SeqCst) {
            return Err(ClientError::Other("connection refused".into()));
        }
        Ok(*self.tip.lock().expect("not poisoned"))
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, ClientError> {
        self.broadcasts.fetch_add(1, Ordering::SeqCst);
        let input_spent = {
            let spent = self.spent.lock().expect("not poisoned");
            tx.input
                .iter()
                .any(|input| spent.contains(&input.previous_output))
        };
        if input_spent {
            return Err(ClientError::Other("bad-txns-inputs-missingorspent".into()));
        }
        if self.reject_broadcast.load(Ordering::SeqCst) {
            return Err(ClientError::Other("min relay fee not met".into()));
        }
        let txid = tx.compute_txid();
        self.set_status(txid, TxStatus::Mempool);
        Ok(txid)
    }
}

/// The input of every parent that [`parent`] builds, for a `seed`.
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

/// A strategy that bumps at the publish.
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
