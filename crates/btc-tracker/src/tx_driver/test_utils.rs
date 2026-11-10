//! Test doubles that the driver test modules share.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
};

use async_trait::async_trait;
use bitcoin::{
    absolute, hashes::Hash, transaction::Version, Amount, BlockHash, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoind_async_client::error::ClientError;
use strata_bridge_primitives::subscription::Subscription;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use super::node::ChainAccess;
use crate::event::{TxEvent, TxStatus};

/// The node that a test scripts: statuses, spent outputs, and open subscriptions.
#[derive(Default)]
pub(super) struct FakeChain {
    pub(super) statuses: Mutex<HashMap<Txid, TxStatus>>,
    pub(super) spent: Mutex<BTreeSet<OutPoint>>,
    /// Rejects every send while set. A send whose input is spent is rejected regardless.
    pub(super) reject_broadcast: AtomicBool,
    pub(super) broadcasts: AtomicUsize,
    pub(super) subscribers: Mutex<HashMap<Txid, UnboundedSender<TxEvent>>>,
    pub(super) subscriptions: AtomicUsize,
    /// Fails every read while set.
    pub(super) rpc_down: AtomicBool,
}

impl FakeChain {
    pub(super) fn set_status(&self, txid: Txid, status: TxStatus) {
        self.statuses
            .lock()
            .expect("not poisoned")
            .insert(txid, status);
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
