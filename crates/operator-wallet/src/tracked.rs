//! A descriptor-only BDK wallet that follows the operator's own bitcoind.
//!
//! One wallet tracks the single script of one descriptor. It holds no key material, so every UTXO,
//! confirmation count, and mempool fact comes from the node, and a signer adds only the signing.
//!
//! Chain state persists through a caller-supplied [`WalletStore`], so a restart resumes from the
//! last persisted checkpoint instead of rescanning from genesis.
//!
//! # What an output is
//!
//! [`output_state`] classifies every output, and [`TrackedWallet::list_utxos`] and
//! [`TrackedWallet::output_states`] both start from it. BDK keeps an unconfirmed transaction
//! canonical after it leaves the mempool, so its own spent marker is not a fact about the chain.
//! The classifier asks the node instead: a spender counts only while a block or the mempool holds
//! it.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    num::NonZeroU32,
    sync::Arc,
};

use bdk_wallet::{
    bitcoin::{
        constants::COINBASE_MATURITY, Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid,
    },
    chain::{BlockId, ChainPosition, ConfirmationBlockTime, FullTxOut},
    descriptor::ExtendedDescriptor,
    KeychainKind, Wallet,
};
use tracing::info;

use crate::{
    config::OperatorWalletConfig,
    persist::{ensure_backend_not_behind, load_or_create, InitError, PersistedWallet, WalletStore},
    plan::FundingInput,
    sync::{Backend, SyncError},
};

/// One output of a wallet as of the last sync, spent or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputState {
    /// Confirmations of the transaction that created the output. `0` if no block holds it.
    pub(crate) confirmations: u32,
    /// What spends the output.
    pub(crate) spend: OutputSpend,
}

/// What spends an output. A spender that left the mempool unconfirmed spends nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OutputSpend {
    /// No block and no mempool transaction spends the output.
    Unspent,
    /// Only mempool transactions spend the output, in txid order. Until a sync finishes, this
    /// holds every unconfirmed spender that the wallet knows.
    InMempool(Vec<Txid>),
    /// A block holds a spend of the output. The count is the confirmations of that spend.
    Confirmed {
        /// Confirmations of the spending transaction.
        confirmations: u32,
    },
}

/// A snapshot of a single UTXO of a tracked wallet.
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// Outpoint identifying this UTXO.
    pub outpoint: OutPoint,
    /// Output amount.
    pub amount: Amount,
    /// Confirmations as of the most recent sync. `0` if the UTXO is in the mempool only
    /// (not yet on chain).
    pub confirmations: u32,
    /// Output script.
    pub script_pubkey: ScriptBuf,
}

impl From<&UtxoInfo> for FundingInput {
    fn from(utxo: &UtxoInfo) -> Self {
        Self {
            outpoint: utxo.outpoint,
            txout: utxo.into(),
        }
    }
}

impl From<UtxoInfo> for TxOut {
    fn from(utxo: UtxoInfo) -> Self {
        TxOut::from(&utxo)
    }
}

impl From<&UtxoInfo> for TxOut {
    fn from(u: &UtxoInfo) -> Self {
        Self {
            value: u.amount,
            script_pubkey: u.script_pubkey.clone(),
        }
    }
}

/// An output of the wallet, as the chain and the wallet graph place it.
type Output = FullTxOut<ConfirmationBlockTime>;

/// The node's mempool as of the last successful sync.
#[derive(Debug, Default)]
struct MempoolView {
    txids: HashSet<Txid>,
    /// Whether the last sync attempt finished. A failed sync can apply blocks and transactions
    /// that `txids` does not reflect, so a spender absent from `txids` proves nothing until a sync
    /// finishes. False while no sync has finished, and after a cancelled sync.
    synced: bool,
    /// Whether any sync has finished since this process loaded the wallet. The store keeps no
    /// mempool transaction, so until then an output that a mempool transaction of an earlier
    /// process spends reads as unspent, and nothing is spendable.
    ever_synced: bool,
}

impl MempoolView {
    /// Whether an unconfirmed spender can still be live. Only a finished sync that does not list
    /// it says no.
    fn may_hold(&self, txid: &Txid) -> bool {
        !self.synced || self.txids.contains(txid)
    }
}

/// A descriptor-only wallet and the node that feeds it.
#[derive(Debug)]
pub struct TrackedWallet<P> {
    wallet: PersistedWallet<P>,
    store: P,
    backend: Backend,
    persist_every_blocks: NonZeroU32,
    /// Cached at construction. The descriptor has one script and does not change at runtime.
    script_pubkey: ScriptBuf,
    /// Decides whether an unconfirmed output is spendable and whether an unconfirmed spender is
    /// live (see [`output_state`]). The txids stay across a failed sync: callers carry on after
    /// one, and an empty set would hide every unconfirmed output.
    mempool: MempoolView,
}

impl<P: WalletStore> TrackedWallet<P> {
    /// Loads the wallet for `descriptor` from `store`, or creates it when the store is empty.
    /// See [`load_or_create`] for the identity checks and the role of `bootstrap_checkpoint`.
    /// A descriptor with a wildcard is refused: the wallet follows one script.
    pub(crate) async fn load_or_create(
        descriptor: ExtendedDescriptor,
        config: &OperatorWalletConfig,
        backend: Backend,
        mut store: P,
        bootstrap_checkpoint: Option<BlockId>,
    ) -> Result<Self, InitError<P::Error>> {
        if descriptor.has_wildcard() {
            return Err(InitError::WildcardDescriptor);
        }
        let wallet =
            load_or_create(&mut store, descriptor, config.network, bootstrap_checkpoint).await?;
        ensure_backend_not_behind(&backend, &wallet).await?;
        let address = wallet.peek_address(KeychainKind::External, 0).address;
        info!(%address, "tracking wallet address");
        Ok(Self {
            script_pubkey: address.script_pubkey(),
            wallet,
            store,
            backend,
            persist_every_blocks: config.persist_every_blocks,
            mempool: MempoolView::default(),
        })
    }

    /// Syncs against the node and persists the staged chain state. See
    /// [`Backend::sync_wallet`].
    pub(crate) async fn sync(&mut self) -> Result<(), SyncError> {
        self.mempool.synced = false;
        self.mempool.txids = self
            .backend
            .sync_wallet(&mut self.wallet, &mut self.store, self.persist_every_blocks)
            .await?;
        self.mempool.synced = true;
        self.mempool.ever_synced = true;
        Ok(())
    }

    /// The script of this wallet.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey.clone()
    }

    /// The local chain tip: the most recent sync checkpoint.
    pub(crate) fn tip(&self) -> BlockId {
        self.wallet.latest_checkpoint().block_id()
    }

    /// Every output the wallet can spend now, confirmed or not.
    ///
    /// An output counts when a block or the mempool holds its own transaction, and no block or
    /// mempool transaction spends it. An output that only a dead transaction spends counts: a
    /// spender that left the mempool unconfirmed does not hold the output.
    pub fn list_utxos(&self) -> Vec<UtxoInfo> {
        spendable_utxos(&self.wallet, &self.mempool).collect()
    }

    /// The transaction `txid`, if this wallet tracks it.
    pub(crate) fn transaction(&self, txid: Txid) -> Option<Arc<Transaction>> {
        self.wallet.tx_graph().get_tx(txid)
    }

    /// The state of each of `outpoints` that is an output of this wallet, spent or not.
    ///
    /// An outpoint is absent when it does not pay this wallet, or when no canonical transaction
    /// creates it: no transaction that the wallet tracks does, or a conflict removed the one that
    /// did. Unlike [`Self::list_utxos`], this reports an output that is spent or not yet spendable,
    /// and says what spends it.
    ///
    /// Before the first sync since load the wallet holds no mempool transaction. Confirmations and
    /// spends in a block are exact then, but an output that only a mempool transaction spends reads
    /// [`OutputSpend::Unspent`].
    pub(crate) fn output_states(
        &self,
        outpoints: &BTreeSet<OutPoint>,
    ) -> BTreeMap<OutPoint, OutputState> {
        states_of(&self.wallet, &self.mempool, outpoints)
    }
}

/// Every output of `wallet` in the canonical view, spent or not.
fn all_outputs(wallet: &Wallet) -> impl Iterator<Item = Output> + '_ {
    outputs_at(
        wallet,
        wallet.spk_index().outpoints().iter().map(|(_, op)| *op),
    )
}

/// Those of `outpoints` that the canonical view of `wallet` holds, spent or not. One pass over
/// the view answers them all, so a caller with many outpoints passes them together.
fn outputs_at<'a>(
    wallet: &'a Wallet,
    outpoints: impl IntoIterator<Item = OutPoint> + 'a,
) -> impl Iterator<Item = Output> + 'a {
    wallet
        .tx_graph()
        .filter_chain_txouts(
            wallet.local_chain(),
            wallet.latest_checkpoint().block_id(),
            outpoints.into_iter().map(|outpoint| ((), outpoint)),
        )
        .map(|(_, output)| output)
}

/// The states of those of `outpoints` that pay `wallet`. A wallet transaction also carries
/// foreign outputs, which the view holds and which say nothing about this wallet, so the index
/// decides.
fn states_of(
    wallet: &Wallet,
    mempool: &MempoolView,
    outpoints: &BTreeSet<OutPoint>,
) -> BTreeMap<OutPoint, OutputState> {
    let ours = outpoints
        .iter()
        .copied()
        .filter(|outpoint| wallet.spk_index().txout(*outpoint).is_some());
    outputs_at(wallet, ours)
        .map(|output| (output.outpoint, output_state(wallet, &output, mempool)))
        .collect()
}

/// Classifies one output of `wallet`. See the module doc.
///
/// A spender that is unconfirmed and absent from `mempool` is dead, and it does not count: the
/// output is free again. An output is spent only while at least one spender lives, so a dead child
/// next to its live replacement leaves the output spent.
fn output_state(wallet: &Wallet, output: &Output, mempool: &MempoolView) -> OutputState {
    let tip_height = wallet.latest_checkpoint().height();
    let spent_in_block = output
        .spent_by
        .as_ref()
        .map(|(position, _)| confirmations_at(position, tip_height))
        .filter(|confirmations| *confirmations > 0);
    let mut spenders: Vec<Txid> = wallet
        .tx_graph()
        .outspends(output.outpoint)
        .iter()
        .copied()
        .filter(|txid| mempool.may_hold(txid))
        .collect();
    spenders.sort_unstable();
    let spend = match (spent_in_block, spenders.is_empty()) {
        (Some(confirmations), _) => OutputSpend::Confirmed { confirmations },
        (None, true) => OutputSpend::Unspent,
        (None, false) => OutputSpend::InMempool(spenders),
    };
    OutputState {
        confirmations: confirmations_at(&output.chain_position, tip_height),
        spend,
    }
}

/// The outputs of `wallet` that it can spend now, with `mempool` as the view of the node.
fn spendable_utxos<'a>(
    wallet: &'a Wallet,
    mempool: &'a MempoolView,
) -> impl Iterator<Item = UtxoInfo> + 'a {
    all_outputs(wallet).filter_map(move |output| {
        let state = output_state(wallet, &output, mempool);
        is_spendable(&output, &state, mempool).then(|| utxo_info(&output, state.confirmations))
    })
}

/// Whether a spend of an output at this depth is valid. A wallet that a test network funds by
/// mining to its address holds coinbase outputs, and a spend of an immature one is invalid.
const fn is_mature(is_coinbase: bool, confirmations: u32) -> bool {
    !is_coinbase || confirmations >= COINBASE_MATURITY
}

/// Whether a transaction can spend `output` now.
///
/// BDK cannot evict a transaction, so one reorged out of the chain and not re-broadcast stays
/// canonical and its outputs keep looking spendable. An unconfirmed output therefore counts only
/// while its own transaction is in the mempool, whatever a failed sync left behind. The state
/// decides the spent half.
fn is_spendable(output: &Output, state: &OutputState, mempool: &MempoolView) -> bool {
    let exists = match output.chain_position {
        ChainPosition::Confirmed { .. } => true,
        ChainPosition::Unconfirmed { .. } => mempool.txids.contains(&output.outpoint.txid),
    };
    mempool.ever_synced
        && exists
        && state.spend == OutputSpend::Unspent
        && is_mature(output.is_on_coinbase, state.confirmations)
}

/// Confirmations of a transaction at `position` when the tip is at `tip_height`. `0` if no block
/// holds it.
const fn confirmations_at(position: &ChainPosition<ConfirmationBlockTime>, tip_height: u32) -> u32 {
    match position {
        ChainPosition::Confirmed { anchor, .. } => tip_height
            .saturating_sub(anchor.block_id.height)
            .saturating_add(1),
        ChainPosition::Unconfirmed { .. } => 0,
    }
}

/// The [`UtxoInfo`] of `output`.
fn utxo_info(output: &Output, confirmations: u32) -> UtxoInfo {
    UtxoInfo {
        outpoint: output.outpoint,
        amount: output.txout.value,
        confirmations,
        script_pubkey: output.txout.script_pubkey.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
    use bdk_wallet::{
        bitcoin::{
            absolute::LockTime,
            bip32::{Xpriv, Xpub},
            hashes::Hash,
            key::TapTweak,
            secp256k1::{Keypair, Message, Secp256k1, SecretKey},
            sighash::{Prevouts, SighashCache},
            transaction::Version,
            Address, Amount, BlockHash, Network, Sequence, TapSighashType, Transaction, TxIn,
            TxOut, Witness,
        },
        chain::{CheckPoint, TxUpdate},
        descriptor, Update,
    };
    use corepc_node::{Conf, Node};
    use serial_test::serial;

    use super::*;
    use crate::test_utils::MemoryStore;

    fn block(height: u32, tag: u8) -> BlockId {
        BlockId {
            height,
            hash: BlockHash::from_byte_array([tag; 32]),
        }
    }

    /// A descriptor-only wallet and the script it owns.
    fn wallet(seed: u8) -> (Wallet, ScriptBuf) {
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid scalar");
        let key = Keypair::from_secret_key(&Secp256k1::new(), &secret)
            .x_only_public_key()
            .0;
        let (desc, ..) = descriptor!(tr(key)).expect("valid descriptor");
        let wallet = Wallet::create_single(desc)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("wallet");
        let script = wallet
            .peek_address(KeychainKind::External, 0)
            .address
            .script_pubkey();
        (wallet, script)
    }

    /// An arbitrary outpoint to spend. Never null: BDK treats a null input as a coinbase, which
    /// it refuses to see unconfirmed.
    fn source(tag: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        }
    }

    /// A transaction spending `source` and paying `sats` to `script`.
    fn pay(source: OutPoint, script: &ScriptBuf, sats: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: source,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: script.clone(),
            }],
        }
    }

    /// Sets the wallet's chain to `blocks` and applies each transaction, anchored at the given
    /// block or, with `None`, seen in the mempool.
    fn apply(wallet: &mut Wallet, blocks: &[BlockId], txs: &[(&Transaction, Option<BlockId>)]) {
        let mut update = TxUpdate::default();
        for (tx, at) in txs {
            update.txs.push(Arc::new((*tx).clone()));
            match at {
                Some(block) => {
                    let anchor = ConfirmationBlockTime {
                        block_id: *block,
                        confirmation_time: u64::from(block.height) * 600,
                    };
                    update.anchors.insert((anchor, tx.compute_txid()));
                }
                None => {
                    update.seen_ats.insert(tx.compute_txid(), 1_000);
                }
            }
        }
        wallet
            .apply_update(Update {
                chain: Some(CheckPoint::from_block_ids(blocks.iter().copied()).expect("ascending")),
                tx_update: update,
                ..Update::default()
            })
            .expect("apply update");
    }

    /// A view from a finished sync that saw exactly `txids`.
    fn seen(txids: &[Txid]) -> MempoolView {
        MempoolView {
            txids: txids.iter().copied().collect(),
            synced: true,
            ever_synced: true,
        }
    }

    fn spendable(wallet: &Wallet, mempool: &MempoolView) -> Vec<OutPoint> {
        spendable_utxos(wallet, mempool)
            .map(|utxo| utxo.outpoint)
            .collect()
    }

    fn state(wallet: &Wallet, outpoint: OutPoint, mempool: &MempoolView) -> OutputState {
        states_of(wallet, mempool, &BTreeSet::from([outpoint]))
            .remove(&outpoint)
            .expect("a wallet output")
    }

    /// A wallet at `h1` with one output of 100 000 sat confirmed there, and that outpoint.
    fn funded() -> (Wallet, ScriptBuf, BlockId, BlockId, OutPoint) {
        let (mut wallet, script) = wallet(9);
        let genesis = wallet.latest_checkpoint().block_id();
        let h1 = block(1, 1);
        let payment = pay(source(1), &script, 100_000);
        apply(&mut wallet, &[genesis, h1], &[(&payment, Some(h1))]);
        (
            wallet,
            script,
            genesis,
            h1,
            OutPoint::new(payment.compute_txid(), 0),
        )
    }

    /// A payment seen in the mempool, confirmed, then reorged out and gone from the mempool. BDK
    /// keeps its stale mempool sighting, so only the current mempool tells it from a live payment.
    #[test]
    fn a_payment_reorged_out_of_the_chain_is_not_spendable() {
        let (mut wallet, script) = wallet(9);
        let genesis = wallet.latest_checkpoint().block_id();
        let payment = pay(source(1), &script, 100_000);
        let live = seen(&[payment.compute_txid()]);
        let h1 = block(1, 1);

        apply(&mut wallet, &[genesis], &[(&payment, None)]);
        assert_eq!(spendable(&wallet, &live).len(), 1, "in the mempool");

        apply(&mut wallet, &[genesis, h1], &[(&payment, Some(h1))]);
        assert_eq!(spendable(&wallet, &seen(&[])).len(), 1, "confirmed");

        apply(&mut wallet, &[genesis, block(1, 11)], &[]);
        assert!(
            matches!(
                wallet.transactions().next().expect("one tx").chain_position,
                ChainPosition::Unconfirmed { last_seen: Some(_) }
            ),
            "BDK reports a stale sighting, not an absence"
        );
        assert!(
            spendable(&wallet, &seen(&[])).is_empty(),
            "gone from the mempool, so not spendable"
        );
        assert_eq!(
            spendable(&wallet, &live).len(),
            1,
            "re-broadcast, so spendable"
        );
    }

    #[test]
    fn an_output_that_a_dead_transaction_spends_is_spendable() {
        let (mut wallet, script, genesis, h1, coin) = funded();
        let child = pay(coin, &script, 90_000);
        apply(&mut wallet, &[genesis, h1], &[(&child, None)]);
        let child_txid = child.compute_txid();

        assert!(
            !spendable(&wallet, &seen(&[child_txid])).contains(&coin),
            "the spender lives, so the output is spent"
        );
        let dead = seen(&[]);
        assert!(
            spendable(&wallet, &dead).contains(&coin),
            "the spender died"
        );
        assert_eq!(
            spendable(&wallet, &dead),
            vec![coin],
            "the output of the dead spender stays hidden"
        );
        assert_eq!(
            state(&wallet, coin, &dead).spend,
            OutputSpend::Unspent,
            "a dead spender spends nothing"
        );
    }

    /// A failed sync can apply a spender and keep the older snapshot, so the snapshot cannot prove
    /// that spender dead.
    #[test]
    fn a_spender_missing_from_an_unfinished_sync_stays_live() {
        let (mut wallet, script, genesis, h1, coin) = funded();
        let child = pay(coin, &script, 90_000);
        apply(&mut wallet, &[genesis, h1], &[(&child, None)]);
        let unsynced = MempoolView {
            txids: HashSet::new(),
            synced: false,
            ever_synced: true,
        };
        assert!(
            !spendable(&wallet, &unsynced).contains(&coin),
            "an unfinished sync keeps the spender live"
        );
        assert_eq!(
            state(&wallet, coin, &unsynced).spend,
            OutputSpend::InMempool(vec![child.compute_txid()]),
            "the spender the wallet knows still counts"
        );
        assert!(
            spendable(&wallet, &seen(&[])).contains(&coin),
            "a finished sync that does not list it proves it dead"
        );
    }

    /// An output of a dead transaction whose only spender is dead too stays hidden: the dead
    /// spender frees it, and its own dead transaction still keeps it out.
    #[test]
    fn a_restored_output_of_a_dead_transaction_stays_hidden() {
        let (mut wallet, script) = wallet(9);
        let genesis = wallet.latest_checkpoint().block_id();
        let payment = pay(source(1), &script, 100_000);
        let coin = OutPoint::new(payment.compute_txid(), 0);
        let child = pay(coin, &script, 90_000);
        apply(&mut wallet, &[genesis], &[(&payment, None), (&child, None)]);
        assert!(
            spendable(&wallet, &seen(&[])).is_empty(),
            "the output of a dead payment is not spendable"
        );
    }

    /// A replaced child left the mempool, and its replacement is there. One live spender keeps
    /// the output spent.
    #[test]
    fn a_dead_child_next_to_a_live_replacement_leaves_the_output_spent() {
        let (mut wallet, script, genesis, h1, coin) = funded();
        let child = pay(coin, &script, 90_000);
        let replacement = pay(coin, &script, 80_000);
        apply(
            &mut wallet,
            &[genesis, h1],
            &[(&child, None), (&replacement, None)],
        );
        let replacement_txid = replacement.compute_txid();
        let mempool = seen(&[replacement_txid]);
        assert!(
            !spendable(&wallet, &mempool).contains(&coin),
            "the live replacement keeps the output spent"
        );
        assert_eq!(
            state(&wallet, coin, &mempool).spend,
            OutputSpend::InMempool(vec![replacement_txid]),
            "only the live replacement is a spender"
        );
    }

    /// A reorg leaves the spender with a stale anchor and no mempool sighting. BDK keeps it
    /// canonical, and no block holds it, so it is dead.
    #[test]
    fn a_spender_with_a_stale_anchor_is_dead() {
        let (mut wallet, script, genesis, h1, coin) = funded();
        let h2 = block(2, 2);
        let child = pay(coin, &script, 90_000);
        apply(&mut wallet, &[genesis, h1, h2], &[(&child, Some(h2))]);
        assert_eq!(
            state(&wallet, coin, &seen(&[])).spend,
            OutputSpend::Confirmed { confirmations: 1 },
            "the block holds the spend"
        );

        apply(&mut wallet, &[genesis, h1, block(2, 22)], &[]);
        assert_eq!(
            state(&wallet, coin, &seen(&[])).spend,
            OutputSpend::Unspent,
            "the reorg took the spend out of the chain"
        );
        assert!(
            spendable(&wallet, &seen(&[])).contains(&coin),
            "the output is free again"
        );
    }

    #[test]
    fn a_confirmed_spend_ends_the_output() {
        let (mut wallet, script, genesis, h1, coin) = funded();
        let h2 = block(2, 2);
        let child = pay(coin, &script, 90_000);
        apply(&mut wallet, &[genesis, h1, h2], &[(&child, Some(h2))]);
        let output = state(&wallet, coin, &seen(&[]));
        assert_eq!(
            output.spend,
            OutputSpend::Confirmed { confirmations: 1 },
            "the spend has the confirmations of its own block"
        );
        assert_eq!(
            output.confirmations, 2,
            "the output has the confirmations of its creating block"
        );
        assert!(
            !spendable(&wallet, &seen(&[])).contains(&coin),
            "a confirmed spend ends the output"
        );
    }

    /// A wallet transaction can pay a foreign script too. That output says nothing about this
    /// wallet, and a lease must not read a state from it.
    #[test]
    fn a_foreign_output_of_a_wallet_transaction_has_no_state() {
        let (mut wallet, script) = wallet(9);
        let genesis = wallet.latest_checkpoint().block_id();
        let h1 = block(1, 1);
        let mut payment = pay(source(1), &script, 100_000);
        payment.output.push(TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: ScriptBuf::new_op_return([1]),
        });
        apply(&mut wallet, &[genesis, h1], &[(&payment, Some(h1))]);
        let txid = payment.compute_txid();
        let (ours, foreign) = (OutPoint::new(txid, 0), OutPoint::new(txid, 1));
        let states = states_of(&wallet, &seen(&[]), &BTreeSet::from([ours, foreign]));
        assert_eq!(
            states.keys().copied().collect::<Vec<_>>(),
            vec![ours],
            "only the output that pays the wallet has a state"
        );
    }

    /// A conflict in the wallet graph removes a transaction from the canonical view, and its
    /// output with it.
    #[test]
    fn an_output_of_a_transaction_that_a_conflict_removed_has_no_state() {
        let (mut wallet, script, genesis, h1, coin) = funded();
        let replaced = pay(coin, &script, 90_000);
        let confirmed = pay(coin, &script, 80_000);
        let h2 = block(2, 2);
        apply(
            &mut wallet,
            &[genesis, h1, h2],
            &[(&replaced, None), (&confirmed, Some(h2))],
        );
        let gone = OutPoint::new(replaced.compute_txid(), 0);
        assert!(
            states_of(&wallet, &seen(&[]), &BTreeSet::from([gone])).is_empty(),
            "the conflict removed the output"
        );
    }

    /// A coinbase restored from a dead spender still waits for maturity.
    #[test]
    fn a_restored_coinbase_output_stays_immature() {
        let (mut wallet, script) = wallet(9);
        let genesis = wallet.latest_checkpoint().block_id();
        let h1 = block(1, 1);
        let mut coinbase = pay(OutPoint::null(), &script, 5_000_000);
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![1, 1]);
        let coin = OutPoint::new(coinbase.compute_txid(), 0);
        let child = pay(coin, &script, 4_000_000);
        apply(
            &mut wallet,
            &[genesis, h1],
            &[(&coinbase, Some(h1)), (&child, None)],
        );
        assert!(
            spendable(&wallet, &seen(&[])).is_empty(),
            "a coinbase output with one confirmation is immature"
        );
    }

    /// A coinbase output of `sats` to `script`, and its outpoint.
    fn coinbase(script: &ScriptBuf, sats: u64) -> (Transaction, OutPoint) {
        let mut coinbase = pay(OutPoint::null(), script, sats);
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![1, 1]);
        let coin = OutPoint::new(coinbase.compute_txid(), 0);
        (coinbase, coin)
    }

    /// The chain from genesis up to `height`, one block per height.
    fn chain_to(genesis: BlockId, height: u32) -> Vec<BlockId> {
        std::iter::once(genesis)
            .chain((1..=height).map(|h| BlockId {
                height: h,
                hash: BlockHash::from_byte_array(h.to_be_bytes().repeat(8).try_into().expect("32")),
            }))
            .collect()
    }

    #[test]
    fn a_coinbase_output_becomes_spendable_at_maturity() {
        let (mut wallet, script) = wallet(9);
        let genesis = wallet.latest_checkpoint().block_id();
        let (coinbase, coin) = coinbase(&script, 5_000_000);
        let immature = chain_to(genesis, COINBASE_MATURITY - 1);
        apply(&mut wallet, &immature, &[(&coinbase, Some(immature[1]))]);
        assert!(
            !spendable(&wallet, &seen(&[])).contains(&coin),
            "one confirmation short of maturity"
        );

        apply(&mut wallet, &chain_to(genesis, COINBASE_MATURITY), &[]);
        assert_eq!(
            spendable(&wallet, &seen(&[])),
            vec![coin],
            "mature at {COINBASE_MATURITY} confirmations"
        );
    }

    #[test]
    fn nothing_is_spendable_before_the_first_sync() {
        let (wallet, _, _, _, coin) = funded();
        assert!(
            spendable(&wallet, &MempoolView::default()).is_empty(),
            "a wallet that never synced offers nothing"
        );
        assert_eq!(
            state(&wallet, coin, &MempoolView::default()).spend,
            OutputSpend::Unspent,
            "the confirmed state is still readable"
        );
    }

    /// A regtest wallet config. The tracked view reads only its network and persist cadence.
    fn config() -> OperatorWalletConfig {
        OperatorWalletConfig::new(0, Network::Regtest)
    }

    #[tokio::test]
    async fn a_descriptor_with_a_wildcard_is_refused() {
        let master = Xpriv::new_master(Network::Regtest, &[7; 32]).expect("master key");
        let xpub = Xpub::from_priv(&Secp256k1::new(), &master);
        let descriptor: ExtendedDescriptor = format!("tr({xpub}/0/*)").parse().expect("descriptor");
        let unreachable = Client::new("http://127.0.0.1:1", Auth::None).expect("rpc client");
        let result = TrackedWallet::load_or_create(
            descriptor,
            &config(),
            Backend::BitcoinCore(Arc::new(unreachable)),
            MemoryStore::new(),
            None,
        )
        .await;
        assert!(
            matches!(result, Err(InitError::WildcardDescriptor)),
            "a wallet tracks one script, so a descriptor that derives many is refused"
        );
    }

    /// A regtest node with mature coinbase in its own wallet.
    fn node() -> Node {
        let node = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind must start");
        mine(&node, 101);
        node
    }

    fn mine(node: &Node, blocks: usize) {
        let address = node.client.new_address().expect("miner address");
        node.client
            .generate_to_address(blocks, &address)
            .expect("mine blocks");
    }

    fn rpc_client(node: &Node) -> Client {
        Client::new(
            &node.rpc_url(),
            Auth::CookieFile(node.params.cookie_file.clone()),
        )
        .expect("rpc client")
    }

    async fn open(
        node: &Node,
        descriptor: ExtendedDescriptor,
        store: MemoryStore,
    ) -> TrackedWallet<MemoryStore> {
        TrackedWallet::load_or_create(
            descriptor,
            &config(),
            Backend::BitcoinCore(Arc::new(rpc_client(node))),
            store,
            None,
        )
        .await
        .expect("open the tracked wallet")
    }

    /// A key-path spend of `coin` by `keypair`, paying `coin` less `fee` to `script`.
    fn spend(coin: &UtxoInfo, keypair: &Keypair, fee: Amount, script: &ScriptBuf) -> Transaction {
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: coin.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: coin.amount - fee,
                script_pubkey: script.clone(),
            }],
        };
        let secp = Secp256k1::new();
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&[TxOut::from(coin)]),
                TapSighashType::Default,
            )
            .expect("sighash");
        let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &tweaked);
        tx.input[0].witness.push(signature.as_ref());
        tx
    }

    /// The state of `coin` in `wallet`.
    fn spend_of(wallet: &TrackedWallet<MemoryStore>, coin: OutPoint) -> OutputSpend {
        wallet
            .output_states(&BTreeSet::from([coin]))
            .remove(&coin)
            .expect("a wallet output")
            .spend
    }

    /// One output followed against a node: funded, spent, through a restart, replaced, and
    /// confirmed.
    #[tokio::test]
    #[serial]
    async fn a_node_backed_wallet_follows_a_spend_to_its_block() {
        let (_, elsewhere) = wallet(3);
        let node = node();
        let keypair = Keypair::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[9; 32]).expect("valid scalar"),
        );
        let (descriptor, ..) =
            descriptor!(tr(keypair.x_only_public_key().0)).expect("valid descriptor");
        let address = Address::p2tr(
            &Secp256k1::new(),
            keypair.x_only_public_key().0,
            None,
            Network::Regtest,
        );
        node.client
            .send_to_address(&address, Amount::from_sat(1_000_000))
            .expect("fund the wallet");
        mine(&node, 1);

        let store = MemoryStore::new();
        let mut wallet = open(&node, descriptor.clone(), store.clone()).await;
        assert!(
            wallet.list_utxos().is_empty(),
            "nothing is spendable before the first sync"
        );
        wallet.sync().await.expect("sync");
        let rpc = rpc_client(&node);
        assert_eq!(
            u64::from(wallet.tip().height),
            rpc.get_block_count().expect("block count"),
            "the sync reaches the node's tip"
        );
        let utxos = wallet.list_utxos();
        assert_eq!(utxos.len(), 1, "the funding output is spendable");
        let coin = utxos[0].clone();
        assert_eq!(
            (coin.amount, coin.confirmations),
            (Amount::from_sat(1_000_000), 1),
            "the funding output carries its value and depth"
        );

        let first = spend(&coin, &keypair, Amount::from_sat(1_000), &elsewhere);
        node.client
            .send_raw_transaction(&first)
            .expect("broadcast the spend");
        wallet.sync().await.expect("sync");
        assert_eq!(
            spend_of(&wallet, coin.outpoint),
            OutputSpend::InMempool(vec![first.compute_txid()]),
            "the mempool spend is visible"
        );
        assert!(
            wallet.list_utxos().is_empty(),
            "a spent output is not offered"
        );

        drop(wallet);
        let mut wallet = open(&node, descriptor, store).await;
        assert_eq!(
            spend_of(&wallet, coin.outpoint),
            OutputSpend::Unspent,
            "the store keeps no mempool transaction, so before a sync the spend is unknown"
        );
        wallet.sync().await.expect("sync");
        assert_eq!(
            spend_of(&wallet, coin.outpoint),
            OutputSpend::InMempool(vec![first.compute_txid()]),
            "the first sync after a restart finds the spend again"
        );

        let replacement = spend(&coin, &keypair, Amount::from_sat(5_000), &elsewhere);
        node.client
            .send_raw_transaction(&replacement)
            .expect("broadcast the replacement");
        wallet.sync().await.expect("sync");
        assert_eq!(
            spend_of(&wallet, coin.outpoint),
            OutputSpend::InMempool(vec![replacement.compute_txid()]),
            "only the replacement spends the output"
        );

        mine(&node, 1);
        wallet.sync().await.expect("sync");
        assert_eq!(
            spend_of(&wallet, coin.outpoint),
            OutputSpend::Confirmed { confirmations: 1 },
            "the block holds the replacement"
        );
    }

    #[test]
    fn mempool_spenders_read_in_txid_order() {
        let (mut wallet, script, genesis, h1, coin) = funded();
        let children: Vec<Transaction> = (0..6)
            .map(|i| pay(coin, &script, 90_000 - i * 1_000))
            .collect();
        let unconfirmed: Vec<_> = children.iter().map(|child| (child, None)).collect();
        apply(&mut wallet, &[genesis, h1], &unconfirmed);
        let mut txids: Vec<Txid> = children.iter().map(Transaction::compute_txid).collect();
        let mempool = seen(&txids);
        txids.sort_unstable();
        assert_eq!(
            state(&wallet, coin, &mempool).spend,
            OutputSpend::InMempool(txids),
            "the spenders do not depend on hash-set order"
        );
    }
}
