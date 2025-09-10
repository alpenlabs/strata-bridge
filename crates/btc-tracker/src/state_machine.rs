use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::Arc,
};

use bitcoin::{Block, BlockHash, Transaction, Txid};
use bitcoincore_zmq::SequenceMessage;
use tracing::{debug, error, info, trace, warn};

use crate::event::{BlockEvent, BlockStatus, TxEvent, TxStatus};

// TODO(proofofkeags): once rust-bitcoin@0.33.x lands this isn't necessary anymore. This is due to a
// bug in rust-bitcoin.
#[cfg(test)]
pub(crate) const BIP34_MIN_HEIGHT: u64 = 17;

/// Type synonym to capture predicates of the following form: Transaction -> bool.
///
/// The choice of using an arc here is intentional so that we can directly compare these predicates
/// (via [`Arc::ptr_eq`]) when managing the active subscription set.
pub type TxPredicate = Arc<dyn Fn(&Transaction) -> bool + Sync + Send>;

/// Keeps track of distinct messages coming in on parallel streams that are all triggered by the
/// same underlying event.
///
/// Depending on the messages we receive and in what order we track the transaction all the way to
/// block inclusion, inferring other states depending on the messages we have received.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TxLifecycle {
    /// The full transaction data of the lifecycle we are tracking.
    raw: Transaction,
    /// An optional [`bitcoin::BlockHash`] that will be populated once the transaction has
    /// been included in a block.
    block: Option<(u64, BlockHash)>,
}

/// The pure state machine that processes all the relevant messages. From there it will
/// emit diffs that describe the new states of transactions.
#[derive(Clone)]
pub(crate) struct BtcZmqSM {
    /// The number of subsequent blocks that must be built on top of a given block for that
    /// block to be considered "buried": the transactions will never be reversed.
    bury_depth: usize,

    /// The set of predicates that are selecting for transactions, the disjunction of which
    /// we care about.
    tx_filters: Vec<TxPredicate>,

    /// The core data structure that holds [`TxLifecycles`] indexed by txid. The encoding
    /// should be understood as follows: If the entry is in the map but the value is None, then
    /// it means we have only received the MempoolAcceptance event. If it's present then we
    /// will definitely have the rawtx event, and if it has been mined into a block, we will
    /// also have that blockhash as well.
    tx_lifecycles: BTreeMap<Txid, Option<TxLifecycle>>,

    // The list of unburied blocks in a queue where the front is the newest block and the
    // back is the oldest "unburied" block
    unburied_blocks: VecDeque<Block>,
}

// Coverage is disabled because when tests pass, most Debug impls will never be invoked.
#[coverage(off)]
impl fmt::Debug for BtcZmqSM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtcZmqSM")
            .field("bury_depth", &self.bury_depth)
            .field(
                "tx_filters",
                &self
                    .tx_filters
                    .iter()
                    .map(|f| format!("{:?}", Arc::as_ptr(f)))
                    .collect::<Vec<String>>(),
            )
            .field("tx_lifecycles", &self.tx_lifecycles)
            .field("unburied_blocks", &self.unburied_blocks)
            .finish()
    }
}
impl PartialEq for BtcZmqSM {
    fn eq(&self, other: &Self) -> bool {
        let filter_eq = self.tx_filters.len() == other.tx_filters.len()
            && self
                .tx_filters
                .iter()
                .zip(other.tx_filters.iter())
                .all(|(a, b)| Arc::ptr_eq(a, b));

        filter_eq
            && self.bury_depth == other.bury_depth
            && self.tx_lifecycles == other.tx_lifecycles
            && self.unburied_blocks == other.unburied_blocks
    }
}

impl Eq for BtcZmqSM {}

impl BtcZmqSM {
    /// Initializes a [`BtcZmqSM`] with the supplied bury_depth. bury_depth is the number of blocks
    /// that must be built on top of a given block before that block's transactions are
    /// considered Buried. It additionally takes a queue of unburied blocks to initialize the state
    /// machine with. The length of this queue is assumed to be equal to the `bury_depth`, or less
    /// if the entire chain is unburied.
    pub(crate) fn init(bury_depth: usize, unburied_blocks: VecDeque<Block>) -> Self {
        info!(%bury_depth, "initializing ZMQ state machine");
        BtcZmqSM {
            bury_depth,
            tx_filters: Vec::new(),
            tx_lifecycles: BTreeMap::new(),
            unburied_blocks,
        }
    }

    /// Takes a [`TxPredicate`] and adds it to the state machine.
    ///
    /// The state machine will track any transaction that matches the disjunction of predicates
    /// added.
    pub(crate) fn add_filter(&mut self, pred: TxPredicate) {
        trace!("adding predicate filter to a ZMQ state machine");
        self.tx_filters.push(pred);
    }

    /// Takes a [`TxPredicate`] that was previously added via [`BtcZmqSM::add_filter`].
    pub(crate) fn rm_filter(&mut self, pred: &TxPredicate) {
        trace!("removing predicate filter from a ZMQ state machine");
        if let Some(idx) = self.tx_filters.iter().position(|p| Arc::ptr_eq(p, pred)) {
            self.tx_filters.swap_remove(idx);
        }
    }

    /// One of the three primary state transition functions of the [`BtcZmqSM`], updating internal
    /// state to reflect the the `rawblock` event.
    pub(crate) fn process_block(&mut self, block: Block) -> (Vec<TxEvent>, Option<BlockEvent>) {
        let block_height_string = block
            .bip34_block_height()
            .map_or("UNKNOWN".to_string(), |h| h.to_string());
        info!(block_height=%block_height_string, block_hash=%block.block_hash(), "processing block");
        trace!(?block, "started processing a block");

        match self.unburied_blocks.front() {
            Some(tip) => {
                if block.header.prev_blockhash == tip.block_hash() {
                    self.unburied_blocks.push_front(block)
                } else {
                    // This implies that we missed a block.
                    //
                    // TODO(proofofkeags): It's also possible that race conditions in the concurrent
                    // stream processing would cause this to fire during a
                    // reorg. Race conditions MUST NOT cause this to fire. This MUST
                    // be fixed.
                    trace!(?block, prev_block=?tip, "block's previous block hash does not match the tip");
                    warn!(block_hash=%block.block_hash(), prev_block_hash=%tip.block_hash(), "block's previous block hash does not match the tip, possible reorg detected");
                    debug_assert!(false, "block's previous block hash does not match the tip");
                }
            }
            // TODO(proofofkeags): fix the problem where we can't notice reorgs close to startup
            // time This is due to the fact that we don't have a full bury depth of
            // history. Fixing this requires us to backfill the block history at startup
            // using the RPC interface, or accepting the blocks newer than the
            // bury depth as an argument to the constructor.
            None => {
                trace!(?block, "no tip found, adding block to unburied blocks");
                self.unburied_blocks.push_front(block);
            }
        }
        let block = self.unburied_blocks.front().unwrap();

        // Now we allocate a Vec will collect the net-new transaction states that need to be
        // distributed.
        let mut diff = Vec::new();

        // When a block is processed, it implicitly means that this is the tip. Even in the case of
        // large fork reorgs each block will be added as the tip in order so we will get all
        // events. When a block is mined, it will cause three types of state transitions:
        // 1. Unknown -> Mined
        // 2. Mempool -> Mined
        // 3. Mined -> Buried
        for matched_tx in block
            .txdata
            .iter()
            .filter(|tx| self.tx_filters.iter().any(|f| f(tx)))
        {
            trace!(?matched_tx, "processing transactions in the block");
            match self.tx_lifecycles.get_mut(&matched_tx.compute_txid()) {
                // This is either the scenario where we haven't yet seen the transaction in any
                // capacity, or where we have a MempoolAcceptance event for it but
                // no other information on it. In either case we handle it the
                // same way, recording the rawtx data in a TxLifecycle and its containing block
                // hash, as well as adding a Mined transaction event to the diff.
                None | Some(None) => {
                    let blockhash = block.block_hash();
                    let height = block.bip34_block_height().unwrap_or(0);
                    debug!(txid=%matched_tx.compute_txid(), blockhash=%blockhash, %height, "processing newly mined transaction");
                    let lifecycle = TxLifecycle {
                        raw: matched_tx.clone(),
                        block: Some((height, blockhash)),
                    };
                    self.tx_lifecycles
                        .insert(matched_tx.compute_txid(), Some(lifecycle));
                    diff.push(TxEvent {
                        rawtx: matched_tx.clone(),
                        status: TxStatus::Mined { blockhash, height },
                    });
                    info!(txid=%matched_tx.compute_txid(), blockhash=%blockhash, %height, "processed newly mined transaction");
                }
                // This means we have seen the rawtx event for this transaction before.
                Some(Some(lifecycle)) => {
                    let blockhash = block.block_hash();
                    let height = block.bip34_block_height().unwrap_or(0);
                    debug!(txid=%matched_tx.compute_txid(), blockhash=%blockhash, %height, "validating already seen transaction");
                    if let Some((_, prior_blockhash)) = lifecycle.block {
                        // This means that it was previously mined. This is pretty weird and so we
                        // include some debug assertions to rule out
                        // violations in our core assumptions.
                        debug_assert!(*matched_tx == lifecycle.raw, "transaction data mismatch");
                        debug_assert!(prior_blockhash != blockhash, "duplicate block message");
                    }

                    // Record the update and add it to the diff.
                    lifecycle.block = Some((height, blockhash));
                    diff.push(TxEvent {
                        rawtx: matched_tx.clone(),
                        status: TxStatus::Mined { blockhash, height },
                    });

                    debug!(txid=%matched_tx.compute_txid(), blockhash=%blockhash, %height, "processed already seen transaction");
                }
            }
        }

        let block_event = if self.unburied_blocks.len() > self.bury_depth {
            if let Some(newly_buried) = self.unburied_blocks.pop_back() {
                // Now that we've handled the Mined transitions. We can take the oldest block we are
                // still tracking and declare all of its relevant transactions
                // buried, and then finally we can clear the buried transactions
                // from the current lifecycle map.
                let blockhash = newly_buried.block_hash();
                let height = newly_buried.bip34_block_height().unwrap_or(0);

                trace!(?newly_buried, %blockhash, %height, "handled all mined transactions, starting to process newly buried transactions");
                info!(%blockhash, %height, "handled all mined transactions, starting to process newly buried transactions from block");

                for buried_tx in newly_buried.txdata.iter() {
                    let buried_txid = buried_tx.compute_txid();

                    trace!(?buried_tx, %buried_txid, %blockhash, %height, "processing buried transaction");

                    self.tx_lifecycles.remove(&buried_txid);
                    if self.tx_filters.iter().any(|f| f(buried_tx)) {
                        diff.push(TxEvent {
                            rawtx: buried_tx.clone(),
                            status: TxStatus::Buried { blockhash, height },
                        });
                    }
                }
                info!(block_height=%height, %blockhash, "processed all buried transactions");
                Some(BlockEvent {
                    block: newly_buried,
                    status: BlockStatus::Buried,
                })
            } else {
                unreachable!("unburied blocks will successfully pop back at lengths > 0");
            }
        } else {
            None
        };

        trace!(?diff, "processed block");
        (diff, block_event)
    }

    /// One of the three primary state transition functions of the [`BtcZmqSM`], updating
    /// internal state to reflect the `rawtx` event.
    pub(crate) fn process_tx(&mut self, tx: Transaction) -> Vec<TxEvent> {
        let txid = tx.compute_txid();
        trace!(?tx, %txid, "filtering transactions");
        if !self.tx_filters.iter().any(|f| f(&tx)) {
            return Vec::new();
        }

        let lifecycle = self.tx_lifecycles.get_mut(&txid);
        match lifecycle {
            // In this case we have never seen any information on this transaction whatsoever.
            None => {
                trace!(?tx, %txid, ?lifecycle, "received new transaction");
                debug!(%txid, ?lifecycle, "received new transaction");
                let lifecycle = TxLifecycle {
                    raw: tx,
                    block: None,
                };

                self.tx_lifecycles.insert(txid, Some(lifecycle));

                // We intentionally DO NOT return the transaction here in the diff because we are
                // unsure of what the status is. We will either immediately get a
                // followup block or a followup sequence which will cause us to emit
                // a new state change.
                Vec::new()
            }
            // In this case we have seen a MempoolAcceptance event for this txid, but haven't seen
            // the actual transaction data yet.
            Some(None) => {
                trace!(?tx, %txid, ?lifecycle, "received MempoolAcceptance event");
                debug!(%txid, ?lifecycle, "received MempoolAcceptance");
                let lifecycle = TxLifecycle {
                    raw: tx.clone(),
                    block: None,
                };

                self.tx_lifecycles.insert(txid, Some(lifecycle));

                // Presence within the map indicates we have already received the sequence message
                // for this but don't yet have any other information, indicating
                // that this rawtx event can generate the Mempool event.
                vec![TxEvent {
                    rawtx: tx,
                    status: TxStatus::Mempool,
                }]
            }
            // In this case we know everything we need to about this transaction, and this is
            // probably a rawtx event that accompanies an upcoming new block event.
            Some(Some(_)) => {
                trace!(?tx, %txid, ?lifecycle, "received duplicate transaction event");
                Vec::new()
            }
        }
    }

    /// One of the three primary state transition functions of the [`BtcZmqSM`],
    /// updating internal state to reflect the `sequence` event.
    pub(crate) fn process_sequence(
        &mut self,
        seq: SequenceMessage,
    ) -> (Vec<TxEvent>, Option<BlockEvent>) {
        match seq {
            SequenceMessage::BlockConnect { .. } => {
                debug!(?seq, "BlockConnect received");
                (vec![], None)
            }
            SequenceMessage::BlockDisconnect { blockhash } => {
                let mut diff = Vec::new();
                // If the block is disconnected we reset all transactions that currently have that
                // blockhash as their containing block.
                trace!(?diff, ?seq, "BlockDisconnect received");
                debug!(?seq, %blockhash, "BlockDisconnect received");
                let blk_evt = if let Some(block) = self.unburied_blocks.front() {
                    if block.block_hash() == blockhash {
                        info!(%blockhash, "block disconnected, removing all included transactions");
                        let block = self.unburied_blocks.pop_front().unwrap();
                        Some(BlockEvent {
                            block,
                            status: BlockStatus::Uncled,
                        })
                    } else {
                        // As far as I can tell, the block connect and disconnect events are done in
                        // "stack order". This means that block connects
                        // happen in chronological order and disconnects happen in reverse
                        // chronological order. If we get a block disconnect event that doesn't
                        // match our current tip then this assumption has
                        // broken down.
                        error!(%blockhash, "invariant violated: out of order block disconnect");
                        panic!("invariant violated: out of order block disconnect");
                    }
                } else {
                    None
                };

                // Clear out all of the transactions we are tracking that were bound to the
                // disconnected block.
                self.tx_lifecycles.retain(|_, v| {
                    match v {
                        Some(lifecycle) => match lifecycle.block {
                            // Only clear the tx if its blockhash matches the blockhash of the
                            // disconnected block.
                            Some((_, blk)) if blk == blockhash => {
                                diff.push(TxEvent {
                                    rawtx: lifecycle.raw.clone(),
                                    status: TxStatus::Unknown,
                                });
                                trace!(tx=?lifecycle.raw, txid=%lifecycle.raw.compute_txid(), "Block disconnected, removing transaction");
                                false
                            }
                            // Otherwise keep it.
                            _ => {
                                trace!(tx=?lifecycle.raw, txid=%lifecycle.raw.compute_txid(), "retaining transaction");
                                true
                            }
                        },
                        None => {
                            trace!(?v, "keeping transaction");
                            true
                        },
                    }
                });
                (diff, blk_evt)
            }
            SequenceMessage::MempoolAcceptance { txid, .. } => {
                debug!(?seq, %txid, "MempoolAcceptance received");
                match self.tx_lifecycles.get_mut(&txid) {
                    // In this case we are well aware of the full transaction data here
                    Some(Some(lifecycle)) => {
                        match lifecycle.block {
                            // This will happen if we receive rawtx before MempoolAcceptance.
                            None => {
                                trace!(?seq, %txid, "received MempoolAcceptance");
                                (
                                    vec![TxEvent {
                                        rawtx: lifecycle.raw.clone(),
                                        status: TxStatus::Mempool,
                                    }],
                                    None,
                                )
                            }
                            // This can happen because there is a race between the rawblock event
                            // delivery and the sequence event for a given transaction. If we
                            // encounter this, we will ignore the MempoolAcceptance.
                            Some(_) => {
                                trace!(?seq, %txid, "ignoring duplicate MempoolAcceptance");
                                (vec![], None)
                            }
                        }
                    }
                    // In this case we have received a MempoolAcceptance event for this txid, but
                    // haven't yet processed the accompanying rawtx event.
                    //
                    // TODO(proofofkeags): relax this. In theory it should never happen but I don't
                    // think it is a material issue if we do. This is currently
                    // a panic to allow us to quickly discover
                    // if this assumption doesn't hold and what it means
                    Some(None) => {
                        panic!("invariant violated: MempoolAcceptance received before rawtx")
                    }
                    // In this case we know nothing of this transaction yet.
                    None => {
                        // We insert a placeholder because we expect the rawtx event to fill in the
                        // remainder of the details.
                        //
                        // NOTE(proofofkeags): since we don't have the raw tx yet we can't check for
                        // predicate matches so this will actually leak
                        // memory until we clear out these placeholders. However, for every
                        // MempoolAcceptance event we are guaranteed to have a corresponding rawtx
                        // event. So this shouldn't cause a memory leak
                        // unless we miss ZMQ events entirely.
                        trace!(?seq, %txid, "saw dangling transaction in mempool");
                        self.tx_lifecycles.insert(txid, None);
                        (vec![], None)
                    }
                }
            }
            SequenceMessage::MempoolRemoval { txid, .. } => {
                match self.tx_lifecycles.remove(&txid) {
                    // This will happen if we've seen the rawtx event for a txid irrespective of its
                    // MempoolAcceptance.
                    //
                    // There is an edge case here that will leak memory. The scenario that can cause
                    // this is when we receive a MempoolAcceptance,
                    // MempoolRemoval, then the rawtx. The only scenario where I
                    // can picture this happening is during mempool replacement cycling attacks.
                    // Even then though it relies on a specific ordering of
                    // events to leak memory. This order of events is possible given
                    // the guarantees of Bitcoin Core's ZMQ interface, but seems unlikely due to
                    // real world timings and the behavior of the ZMQ streams.
                    //
                    // For now I think we can leave this alone, but if we notice memory leaks in a
                    // live deployment this will be one of the places to look.
                    Some(Some(lifecycle)) => {
                        trace!(?seq, %txid, "MempoolRemoval received for a transaction with some lifecycle");
                        let diff = vec![TxEvent {
                            rawtx: lifecycle.raw,
                            status: TxStatus::Unknown,
                        }];
                        (diff, None)
                    }
                    // This will happen if we've only received a MempoolAcceptance event, the
                    // removal will cancel it fully.
                    Some(None) => {
                        trace!(?seq, %txid, "transaction removed from mempool");
                        (vec![], None)
                    }
                    // This happens if we've never heard anything about this transaction before.
                    None => {
                        trace!(?seq, %txid, "observed removal of a new transaction from mempool");
                        (vec![], None)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod prop_tests {
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::Arc,
    };

    use bitcoin::{
        absolute::{Height, LockTime},
        block,
        hashes::{sha256d, Hash},
        key::Secp256k1,
        script::{write_scriptint, Instruction, PushBytesBuf},
        secp256k1::{All, SecretKey},
        transaction, Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };
    use bitcoincore_zmq::SequenceMessage;
    use prop::array::uniform16;
    use proptest::prelude::*;

    use super::TxPredicate;
    use crate::{
        constants::DEFAULT_BURY_DEPTH,
        event::{TxEvent, TxStatus},
        state_machine::{BtcZmqSM, BIP34_MIN_HEIGHT},
    };

    // Create a DebuggablePredicate type so we can generate dynamic predicates for the tests in this
    // module.
    struct DebuggablePredicate {
        pred: TxPredicate,
        description: String,
    }

    // Coverage is disabled because when tests pass, most Debug impls will never be invoked.
    #[coverage(off)]
    impl std::fmt::Debug for DebuggablePredicate {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.description)
        }
    }

    // Generates an amount between 1sat and 21MBTC.
    prop_compose! {
        fn arb_amount()(sats in 1..2100000000000000u64) -> Amount {
            Amount::from_sat(sats)
        }
    }

    // Generates a random 32 byte hash as a Txid`.
    prop_compose! {
        fn arb_txid()(bs in any::<[u8; 32]>()) -> Txid {
            Txid::from_raw_hash(*sha256d::Hash::from_bytes_ref(&bs))
        }
    }

    // Generates a random OutPoint reference.
    prop_compose! {
        fn arb_outpoint()(txid in arb_txid(), vout in 0..100u32) -> OutPoint {
            OutPoint { txid, vout }
        }
    }

    // Generates a fully defined TxIn.
    prop_compose! {
        fn arb_input()(
            previous_output in arb_outpoint(),
            script_sig in any::<[u8; 32]>().prop_map(|b| ScriptBuf::from_bytes(b.to_vec())),
            sequence in any::<u32>().prop_map(Sequence::from_consensus),
        ) -> TxIn {
            TxIn {
                previous_output,
                script_sig,
                sequence,
                witness: Witness::new(),
            }
        }
    }

    // Generates a fully defined TxOut.
    prop_compose! {
        fn arb_output()(
            value in arb_amount(),
            script_pubkey in any::<[u8; 32]>().prop_map(|b| ScriptBuf::from_bytes(b.to_vec()))
        ) -> TxOut {
            TxOut {
                value,
                script_pubkey,
            }
        }
    }

    // Generates a random Transaction. It is not guaranteed to be consensus valid.
    prop_compose! {
        fn arb_transaction()(
            max_num_ins in 2..100u32,
            max_num_outs in 2..100u32
        )(
            ins in prop::collection::vec(arb_input(), (1, max_num_ins as usize)),
            outs in prop::collection::vec(arb_output(), (1, max_num_outs as usize))
        ) -> Transaction {
            Transaction {
                version: transaction::Version::TWO,
                lock_time: LockTime::Blocks(Height::ZERO),
                input: ins,
                output: outs,
            }
        }
    }

    // Generates a block that contains 32 random transactions. The argument defines the blockhash of
    // the block this block builds on top of.
    prop_compose! {
        fn arb_block(prev_height: u64, prev_blockhash: BlockHash)(
            txdata in uniform16(arb_transaction()),
            time in any::<u32>(),
        ) -> Block {
            assert!(
                prev_height >= BIP34_MIN_HEIGHT,
                "can't encode bip34 height for blocks prior to 17"
            );
            let header = block::Header {
                version: block::Version::TWO,
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time,
                bits: CompactTarget::from_consensus(u32::MAX),
                nonce: 0,
            };

            // This set of code is needed to ensure the blocks we produce in our test suite can have
            // their heights extracted properly in the code under test.
            let mut bip34_scriptsig = ScriptBuf::new();
            let mut buf = PushBytesBuf::new();
            let height = prev_height + 1;
            let mut height_bytes = [0; 8];
            let num_written = write_scriptint(&mut height_bytes, height as i64);

            #[allow(clippy::needless_range_loop)]
            for i in 0..num_written {
                buf.push(height_bytes[i]).unwrap();
            }

            bip34_scriptsig.push_instruction(Instruction::PushBytes(&buf));
            let pubkey = "0000000000000000000000000000000000000000000000000000000000000001"
                .parse::<SecretKey>()
                .unwrap()
                .public_key(&Secp256k1::<All>::gen_new());
            let mut txdata_with_coinbase = vec![Transaction{
                version: transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: bip34_scriptsig,
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_btc(50.0).unwrap(),
                    script_pubkey: ScriptBuf::new_p2pk(&bitcoin::PublicKey::new(pubkey)),
                }]
            }];

            // Actually add the rest of the transaction data
            txdata_with_coinbase.extend(txdata.into_iter());

            let mut blk = Block {
                header,
                txdata: txdata_with_coinbase,
            };

            blk.header.merkle_root = blk.compute_merkle_root().unwrap();
            blk
        }
    }

    // Generates a chain of size "length" that is anchored to "prev_blockhash".
    fn arb_chain(
        prev_height: u64,
        prev_blockhash: BlockHash,
        length: usize,
    ) -> BoxedStrategy<VecDeque<Block>> {
        if length == 0 {
            return Just(VecDeque::new()).boxed();
        }

        let tail = arb_chain(prev_height, prev_blockhash, length - 1);
        tail.prop_flat_map(move |t| {
            let prev = match t.front() {
                Some(b) => (b.bip34_block_height().unwrap_or(0), b.block_hash()),
                None => (prev_height, prev_blockhash),
            };
            arb_block(prev.0, prev.1).prop_map(move |b| {
                let mut v = t.clone();
                v.push_front(b);
                v
            })
        })
        .boxed()
    }

    // Generates a random predicate that will shrink towards including all transactions.
    prop_compose! {
        fn arb_predicate()(modsize in 1..255u8) -> DebuggablePredicate {
            let pred = move |tx: &Transaction| tx.compute_txid().to_raw_hash().to_byte_array()[31].is_multiple_of(modsize);
            DebuggablePredicate {
                pred: std::sync::Arc::new(pred),
                description: format!("txid mod {modsize} == 0"),
            }
        }
    }

    proptest! {

        #[test]
        fn arb_block_has_height(block in arb_block(BIP34_MIN_HEIGHT, Hash::all_zeros())) {
            prop_assert_eq!(block.bip34_block_height(), Ok(18))
        }

        // Ensures that the transactions that appear in the diffs generated by the BtcZmqSM's state
        // transition functions all match the predicate we added. (Consistency)
        #[test]
        fn only_matched_transactions_in_diffs(pred in arb_predicate(), block in arb_block(BIP34_MIN_HEIGHT, Hash::all_zeros())) {
            let mut sm = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm.add_filter(pred.pred.clone());
            let (diff, _block_event) = sm.process_block(block);
            for event in diff.iter() {
                prop_assert!((pred.pred)(&event.rawtx))
            }
        }

        // Ensures that all of the transactions match the predicate we add to the state machine
        // appear in the diffs generated by the BtcZmqSM. (Completeness)
        #[test]
        fn all_matched_transactions_in_diffs(pred in arb_predicate(), block in arb_block(BIP34_MIN_HEIGHT, Hash::all_zeros())) {
            let mut sm = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm.add_filter(pred.pred.clone());
            let (diff, _block_event) = sm.process_block(block.clone());
            prop_assert_eq!(diff.len(), block.txdata.iter().filter(|tx| (pred.pred)(tx)).count())
        }

        // Ensures that an unaccompanied process_tx yields an empty diff.
        //
        // This serves as an important base case to ensure the uniqueness of events
        #[test]
        fn lone_process_tx_yields_empty_diff(tx in arb_transaction()) {
            let mut sm = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm.add_filter(std::sync::Arc::new(|_|true));
            let diff = sm.process_tx(tx);
            prop_assert_eq!(diff, Vec::new());
        }

        // Ensures that the order of process_tx and a corresponding MempoolAcceptance
        // (process_sequence) does not impact the total event diff when both of these are received.
        // (seq-tx Commutativity)
        #[test]
        fn seq_tx_commutativity(tx in arb_transaction()) {
            let txid = tx.compute_txid();
            let mempool_sequence = 0u64;

            let mut sm1 = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm1.add_filter(std::sync::Arc::new(|_|true));

            let diff_tx_1 = sm1.process_tx(tx.clone());
            let diff_seq_1 = sm1.process_sequence(SequenceMessage::MempoolAcceptance{ txid, mempool_sequence });

            let diff_tx_1_set = BTreeSet::from_iter(diff_tx_1.into_iter());
            let diff_seq_1_set = BTreeSet::from_iter(diff_seq_1.0.into_iter());
            let diff_1 = diff_tx_1_set.union(&diff_seq_1_set).cloned().collect::<BTreeSet<TxEvent>>();

            let mut sm2 = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm2.add_filter(std::sync::Arc::new(|_|true));

            let diff_seq_2 = sm2.process_sequence(SequenceMessage::MempoolAcceptance{ txid, mempool_sequence });
            let diff_tx_2 = sm2.process_tx(tx);

            let diff_tx_2_set = BTreeSet::from_iter(diff_tx_2.into_iter());
            let diff_seq_2_set = BTreeSet::from_iter(diff_seq_2.0.into_iter());
            let diff_2 = diff_tx_2_set.union(&diff_seq_2_set).cloned().collect::<BTreeSet<TxEvent>>();

            prop_assert_eq!(diff_1, diff_2);
        }

        // Ensures that a BlockDisconnect event yields an Unknown event for every transaction in
        // that block.
        #[test]
        fn block_disconnect_drops_all_transactions(
            pred in arb_predicate(),
            block in arb_block(BIP34_MIN_HEIGHT, Hash::all_zeros()),
        ) {
            let blockhash = block.block_hash();

            let mut sm = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm.add_filter(pred.pred);
            let (diff_mined, _block_event) = sm.process_block(block);
            let is_mined = |s: &TxStatus| matches!(s, TxStatus::Mined{..});
            prop_assert!(diff_mined.iter().map(|event| &event.status).all(is_mined));

            let diff_dropped = sm.process_sequence(SequenceMessage::BlockDisconnect{ blockhash});
            prop_assert!(diff_dropped.0.iter().map(|event| &event.status).all(|s| *s == TxStatus::Unknown));
        }

        // Ensures that adding a full bury_depth length chain of blocks on top of a block yields a
        // Buried event for every transaction in that block.
        #[test]
        fn transactions_eventually_buried(mut chain in arb_chain(17, Hash::all_zeros(), 7)) {
            let mut sm = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm.add_filter(std::sync::Arc::new(|_|true));

            let oldest = chain.pop_back().unwrap();
            let (diff, _block_event) = sm.process_block(oldest);

            let mut diff_last = Vec::new();
            for block in chain.into_iter().rev() {
                diff_last = sm.process_block(block).0;
            }

            let to_be_buried = diff.into_iter().map(|event| event.rawtx.compute_txid()).collect::<BTreeSet<Txid>>();
            let is_buried = diff_last.into_iter().filter_map(|event| if matches!(event.status, TxStatus::Buried{..}) {
                Some(event.rawtx.compute_txid())
            } else {
                None
            }).collect::<BTreeSet<Txid>>();

            prop_assert_eq!(to_be_buried, is_buried);
        }

        // Ensures that receiving both a MempoolAcceptance and tx event yields a Mempool event.
        // (seq-tx Completeness)
        #[test]
        fn seq_and_tx_make_mempool(tx in arb_transaction()) {
            let mut sm = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());

            sm.add_filter(Arc::new(|_|true));

            let diff = sm.process_sequence(SequenceMessage::MempoolAcceptance { txid: tx.compute_txid(), mempool_sequence: 0 });
            prop_assert!(diff.0.is_empty());

            let diff = sm.process_tx(tx.clone());
            prop_assert_eq!(diff, vec![TxEvent { rawtx: tx, status: TxStatus::Mempool }]);
        }

        // Ensures that removing a filter after adding it results in an identical state machine.
        // (filter Invertibility)
        #[test]
        fn filter_rm_inverts_add(pred in arb_predicate()) {
            let sm_ref = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            let mut sm = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());

            sm.add_filter(pred.pred.clone());
            sm.rm_filter(&pred.pred);

            prop_assert_eq!(sm, sm_ref);
        }

        // Ensures that a processing of a MempoolRemoval inverts the processing of a
        // MempoolAcceptance, even if there is an interceding `rawtx` event. (Mempool Invertibility)
        #[test]
        fn mempool_removal_inverts_acceptance(tx in arb_transaction(), include_raw in any::<bool>()) {
            let mut sm_ref = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm_ref.add_filter(Arc::new(|_|true));
            let mut sm = sm_ref.clone();

            let txid = tx.compute_txid();
            sm.process_sequence(SequenceMessage::MempoolAcceptance { txid, mempool_sequence: 0 });
            if include_raw {
                sm.process_tx(tx);
            }
            sm.process_sequence(SequenceMessage::MempoolRemoval { txid, mempool_sequence: 0 });

            prop_assert_eq!(sm, sm_ref);
        }

        // Ensures that processing a BlockDisconnect event inverts the processing of a prior
        // `rawblock` event. (Block Invertibility)
        #[test]
        fn block_disconnect_inverts_block(
            mempool_tx in arb_transaction(),
            sequence_only in any::<bool>(),
            mut chain in arb_chain(17, Hash::all_zeros(), 2),
        ) {
            let mut sm_ref = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm_ref.add_filter(Arc::new(|_|true));

            // To ensure that we have a more interesting state machine than just the block we want
            // to process we include transactions that aren't included in any block.
            if sequence_only {
                sm_ref.process_sequence(
                    SequenceMessage::MempoolAcceptance {
                        txid: mempool_tx.compute_txid(),
                        mempool_sequence: 0
                    },
                );
            } else {
                sm_ref.process_tx(mempool_tx);
            }

            // We process a block that isn't the one we plan to disconnect just to ensure the state
            // machine has a richer state.
            sm_ref.process_block(chain.pop_back().unwrap());

            // Fork the state machine.
            let mut sm = sm_ref.clone();

            let block = chain.pop_back().unwrap();
            let blockhash = block.block_hash();
            sm.process_block(block);
            sm.process_sequence(SequenceMessage::BlockDisconnect { blockhash });

            prop_assert_eq!(sm, sm_ref);
        }

        // Ensures that a `rawtx` event sampled from a `rawblock` event is idempotent following the
        // `rawblock` event. (block-tx Idempotence)
        #[test]
        fn tx_after_block_idempotence(block in arb_block(BIP34_MIN_HEIGHT, Hash::all_zeros())) {
            let mut sm_ref = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm_ref.add_filter(Arc::new(|_|true));
            sm_ref.process_block(block.clone());
            let mut sm = sm_ref.clone();

            for tx in block.txdata {
                sm.process_tx(tx);
                prop_assert_eq!(&sm, &sm_ref);
            }
        }

        // Ensures that we end up with the same result irrespective of the processing order of a
        // `rawblock` and its accompanying rawtx events. (tx-block Commutativity)
        #[test]
        fn tx_block_commutativity(block in arb_block(BIP34_MIN_HEIGHT, Hash::all_zeros())) {
            let mut sm_base = BtcZmqSM::init(DEFAULT_BURY_DEPTH, VecDeque::new());
            sm_base.add_filter(Arc::new(|_|true));
            let mut sm_block_first = sm_base.clone();
            let mut sm_tx_first = sm_base;

            sm_block_first.process_block(block.clone());
            for tx in block.clone().txdata {
                sm_block_first.process_tx(tx);
            }

            for tx in block.clone().txdata {
                sm_tx_first.process_tx(tx);
            }
            sm_tx_first.process_block(block);

            prop_assert_eq!(sm_tx_first, sm_block_first);
        }
    }
}
