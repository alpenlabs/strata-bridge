//! Native BDK-backed implementation of [`GeneralWallet`].
//!
//! The native wallet holds the operator's general-funds descriptor (`tr(general_pubkey)`) but
//! never holds private keys. Per the [`GeneralWallet`] signing contract, every PSBT this impl
//! returns carries `witness_utxo` and `tap_internal_key` on its inputs but no signatures —
//! the caller signs downstream.

use std::{
    collections::BTreeSet,
    sync::{Mutex, MutexGuard},
};

use bdk_wallet::{
    bitcoin::{
        psbt::Input as PsbtInput, taproot::LeafVersion, Address, Amount, FeeRate, Network,
        OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Witness, XOnlyPublicKey,
    },
    descriptor,
    error::CreateTxError,
    KeychainKind, TxOrdering, Wallet,
};
use thiserror::Error;
use tracing::info;

use crate::{
    general::{
        local_output_to_utxo_info, AnchorInfo, FundedPsbt, GeneralWallet, ReplacedChild, UtxoInfo,
        TAPROOT_KEY_PATH_SAT_WEIGHT,
    },
    sync::{Backend, SyncError},
};

/// Native BDK-backed general wallet.
#[derive(Debug)]
pub struct NativeGeneralWallet {
    /// Cached at construction; the BDK descriptor doesn't change at runtime.
    script_pubkey: ScriptBuf,
    /// The BDK wallet.
    ///
    /// BDK builds a transaction through `&mut Wallet`, and [`GeneralWallet`] builds through
    /// `&self`. The lock closes that gap. Every critical section here is synchronous, so the
    /// lock is never held across an await point.
    wallet: Mutex<Wallet>,
    sync_backend: Backend,
}

/// Locks the BDK wallet and recovers from a poisoned lock.
///
/// A poisoned lock means a panic happened inside one of the critical sections of this file.
/// Each one is a single BDK call, so the wallet state stays consistent, and one panic must
/// not stop every later transaction that the operator builds.
fn lock_wallet(wallet: &Mutex<Wallet>) -> MutexGuard<'_, Wallet> {
    wallet
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl NativeGeneralWallet {
    /// Constructs a native general wallet from the operator's general x-only public key.
    pub fn new(general_pubkey: XOnlyPublicKey, network: Network, sync_backend: Backend) -> Self {
        let (desc, ..) = descriptor!(tr(general_pubkey)).expect("valid tr() descriptor");
        let wallet = Wallet::create_single(desc)
            .network(network)
            .create_wallet_no_persist()
            .expect("wallet creation must not fail");
        let address = wallet.peek_address(KeychainKind::External, 0).address;
        info!("general wallet address: {address}");
        let script_pubkey = address.script_pubkey();
        Self {
            script_pubkey,
            wallet: Mutex::new(wallet),
            sync_backend,
        }
    }
}

/// Error type for the native general wallet impl.
#[derive(Debug, Error)]
pub enum NativeGeneralError {
    /// BDK failed to build a transaction (insufficient funds, no UTXOs, ...).
    #[error("bdk create-tx: {0}")]
    CreateTx(#[from] CreateTxError),
    /// Chain sync (block / mempool fetch) failed.
    #[error("wallet sync: {0:?}")]
    Sync(SyncError),
    /// `anchor.vout` indexes past the end of `parent.output`.
    #[error("anchor vout {vout} out of range for parent with {parent_outputs} outputs")]
    AnchorVoutOutOfRange {
        /// The requested anchor vout.
        vout: u32,
        /// Number of outputs on `parent`.
        parent_outputs: usize,
    },
    /// BDK rejected the foreign-utxo insertion of the parent's anchor (typically because it
    /// could not parse the script_pubkey).
    #[error("bdk add_foreign_utxo for anchor: {0}")]
    AnchorForeignUtxo(String),
    /// BDK rejected one of the funding outpoints this impl selected.
    #[error("bdk add_utxos for CPFP funding: {0}")]
    FundingUtxo(String),
    /// The built child does not have the input count it was priced for, so its fee no longer
    /// matches its size. Refuse it rather than broadcast a package at the wrong rate.
    #[error("CPFP child has {actual} inputs, priced for {expected}")]
    UnexpectedInputCount {
        /// Anchor plus the funding inputs that `select_funding` chose.
        expected: usize,
        /// Inputs the builder actually produced.
        actual: usize,
    },
    /// Every spendable wallet UTXO together with the anchor still cannot pay the child's fee
    /// and leave a spendable drain output.
    #[error("insufficient funds for CPFP child: {available} sat available, {needed} sat needed")]
    InsufficientFunding {
        /// Anchor value plus every candidate wallet UTXO.
        available: u64,
        /// Fee for that shape, plus the dust threshold for the drain output.
        needed: u64,
    },
}

impl crate::ErrorPermanence for NativeGeneralError {
    fn is_permanent(&self) -> bool {
        match self {
            // The output count of a signed parent never changes, and a script that BDK cannot
            // read as a foreign UTXO stays unreadable. Every later attempt for this parent
            // fails at the same step.
            Self::AnchorVoutOutOfRange { .. } | Self::AnchorForeignUtxo(_) => true,
            // Funds arrive, the chain moves, and selection picks a different set. Each of
            // these passes on a later attempt.
            Self::CreateTx(_)
            | Self::Sync(_)
            | Self::FundingUtxo(_)
            | Self::UnexpectedInputCount { .. }
            | Self::InsufficientFunding { .. } => false,
        }
    }
}

impl GeneralWallet for NativeGeneralWallet {
    type Error = NativeGeneralError;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        // `get_mut` and not a lock: `&mut self` already proves that nothing else holds the
        // wallet, so the sync can await without a guard alive across it.
        self.sync_backend
            .sync_wallet(
                self.wallet
                    .get_mut()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
            .await
            .map_err(NativeGeneralError::Sync)
    }

    fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey.clone()
    }

    fn payout_descriptor(&self) -> bitcoin_bosd::Descriptor {
        // The wallet's own receive script (the BIP-341 tap-tweaked general key), wrapped as
        // a BOSD descriptor — the same construction the operator wallet used before this
        // became backend-specific. Deriving it from the receive script makes
        // divergence structurally impossible: payouts land on an ordinary wallet UTXO that
        // BDK tracks, and the tap-tweaking wallet signer can spend (and CPFP-bump) it.
        //
        // Wrapping the *raw* general key instead would be subtly catastrophic: BOSD treats
        // a P2TR payload as the already-tweaked OUTPUT key (`dangerous_assume_tweaked`), so
        // the payout output would be keyed to an untweaked point — invisible to the BDK
        // descriptor and unspendable by every signer wired in production (they all
        // tap-tweak).
        //
        // Known window (STR-3427, lease lifecycle): because payouts are ordinary wallet
        // UTXOs, an in-mempool payout output is auto-selectable as funding by a concurrent
        // duty until a bump child spends it — leases only cover child-selected funding
        // inputs, never the payout outpoint itself. Bounded consequence: the duty tx ends
        // up as the parent's de-facto TRUC child (it pays real fees, so the parent still
        // confirms) and any later explicit bump bounces off RBF against it, noisily.
        let wallet = lock_wallet(&self.wallet);
        let address = Address::from_script(&self.script_pubkey, wallet.network())
            .expect("wallet receive script is a standard P2TR script");
        bitcoin_bosd::Descriptor::try_from(address)
            .expect("standard address converts to a BOSD descriptor")
    }

    fn list_utxos(&self) -> Vec<UtxoInfo> {
        let wallet = lock_wallet(&self.wallet);
        let tip = wallet.latest_checkpoint().height();
        wallet
            .list_unspent()
            .map(|lo| local_output_to_utxo_info(&lo, tip))
            .collect()
    }

    async fn fund_v3_transaction(
        &self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        let psbt = build_v3_psbt(
            &mut lock_wallet(&self.wallet),
            &outputs,
            explicit_inputs,
            fee_rate,
            exclude,
        )?;
        Ok(FundedPsbt { psbt })
    }

    async fn build_cpfp_child(
        &self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        target_pkg_fee_rate: FeeRate,
        exclude: &[OutPoint],
        replaced: ReplacedChild<'_>,
    ) -> Result<FundedPsbt, Self::Error> {
        build_cpfp_child_impl(
            &mut lock_wallet(&self.wallet),
            parent,
            parent_fee,
            anchor,
            target_pkg_fee_rate,
            exclude,
            replaced,
        )
    }

    async fn sign_owned_inputs(
        &self,
        _tx: &Transaction,
        input_indices: &[usize],
        _prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, Self::Error> {
        // Descriptor-only: this backend holds no key material, so it signs nothing — the caller
        // signs these inputs downstream via secret-service.
        Ok(vec![None; input_indices.len()])
    }
}

/// Implementation of [`NativeGeneralWallet::build_cpfp_child`], factored into a free function
/// so it doesn't borrow `self` through the trait method and can be unit-tested without an
/// outer `NativeGeneralWallet`.
///
/// The child pays an absolute fee, and this function picks its own inputs.
///
/// BDK knows nothing about the parent, so it cannot price a package. This function computes the
/// fee itself: `target × (parent.vbytes + child.vbytes) − parent_fee`. That formula needs
/// `child.vbytes`, which depends on how many funding inputs the child has.
///
/// Therefore the inputs are chosen here, before the fee is computed, by
/// [`select_funding`]. Once the input count is fixed the child's size is known exactly, so the
/// fee is exact too, and the package lands on the target rate rather than near it.
///
/// Earlier revisions left the choice to BDK and tried to predict the result. That does not work.
/// An absolute fee needs an upper bound on the child size, and no upper bound is knowable before
/// selection runs. Predicting low makes the package underpay, and the prediction was wrong for
/// any script-path anchor and for any child that drew more than one funding input.
///
/// The anchor enters through `add_foreign_utxo`, because the wallet does not hold the anchor key
/// and cannot recognize the outpoint. The parent is usually not broadcast yet, so the wallet
/// cannot see it at all. The PSBT input carries `witness_utxo` plus either `tap_internal_key`
/// (key path) or `tap_scripts` (script path), and a witness-weight estimate. The caller signs
/// that input downstream.
fn build_cpfp_child_impl(
    wallet: &mut Wallet,
    parent: &Transaction,
    parent_fee: Amount,
    anchor: AnchorInfo,
    target_pkg_fee_rate: FeeRate,
    exclude: &[OutPoint],
    replaced: ReplacedChild<'_>,
) -> Result<FundedPsbt, NativeGeneralError> {
    let anchor_vout = anchor.vout();
    let anchor_outpoint = OutPoint {
        txid: parent.compute_txid(),
        vout: anchor_vout,
    };
    let anchor_txout = parent
        .output
        .get(anchor_vout as usize)
        .ok_or(NativeGeneralError::AnchorVoutOutOfRange {
            vout: anchor_vout,
            parent_outputs: parent.output.len(),
        })?
        .clone();

    // ── Compute the child's absolute fee ────────────────────────────────────
    //
    // The package math:
    //   package_vbytes = parent.vbytes + child_estimate
    //   child_fee     = target_pkg_fee_rate × package_vbytes − parent_fee
    //
    // We don't know child.vbytes yet — it depends on how many funding inputs BDK picks, and
    // with an absolute fee an UNDER-estimate means the package silently underpays (the fixed
    // fee spread over more vbytes). So rather than trusting one guess, seed a derived
    // estimate and then converge on what BDK actually produced — see the build loop below.
    let parent_vbytes: u64 = parent
        .vsize()
        .try_into()
        .expect("tx.vsize() fits in u64 on every supported target");
    let fee_for = |child_vbytes: u64| -> u64 {
        let pkg_vbytes = parent_vbytes.saturating_add(child_vbytes);
        // Round up. Truncating pays up to 1 sat under the target whenever the rate has
        // sat/kwu granularity (fractional sat/vB — the common case from `estimatesmartfee`),
        // and an underpaid package sits exactly at the node's acceptance boundary.
        let target_pkg_fee_sat = target_pkg_fee_rate
            .to_sat_per_kwu()
            .saturating_mul(pkg_vbytes.saturating_mul(4))
            .div_ceil(1000);
        target_pkg_fee_sat.saturating_sub(parent_fee.to_sat())
    };

    // ── Build the child ─────────────────────────────────────────────────────

    // Note there is no `unspendable()` call here. It would do nothing: manual selection
    // overrides it, and BDK skips the filter it feeds entirely. The anchor and the excluded
    // outpoints are kept out by `select_funding` instead.
    let exclude_set: BTreeSet<OutPoint> = exclude.iter().copied().collect();

    // The child has no external recipient: it's a self-spend that consolidates the anchor
    // value + selected funding back to the wallet (minus fee). Use `drain_to` to make this
    // explicit, otherwise BDK rejects with `NoRecipients`.
    let drain_script = wallet
        .peek_address(KeychainKind::External, 0)
        .address
        .script_pubkey();

    // Choose the funding inputs here rather than leaving the choice to BDK.
    //
    // The child's fee depends on its size, and its size depends on how many funding inputs it
    // has. If BDK picks the inputs, we can only guess the size before the fact and check it
    // after, which is what earlier revisions did. Choosing the inputs ourselves collapses that
    // circularity: once the input count is fixed, the size is known exactly, so the fee is
    // exact too.
    let anchor_value_sat = anchor_txout.value.to_sat();
    let selection = select_funding(
        wallet,
        &exclude_set,
        anchor_outpoint,
        anchor_value_sat,
        &anchor,
        &fee_for,
        replaced,
    )?;

    // Resolve the witness data of any replaced funding inputs up front, before the builder
    // takes its mutable borrow of the wallet. Once the wallet has observed the prior child
    // (any sync between two bumps applies the mempool), these outpoints read as spent, so
    // `add_utxo` refuses them and they must enter as foreign inputs instead — with a
    // `witness_utxo`, which is all the downstream signer needs.
    let replaced_txouts: Vec<(OutPoint, TxOut)> = replaced
        .inputs
        .iter()
        .filter_map(|&outpoint| {
            let wtx = wallet.get_tx(outpoint.txid)?;
            let txout = wtx.tx_node.tx.output.get(outpoint.vout as usize)?.clone();
            Some((outpoint, txout))
        })
        .collect();

    // Build the foreign UTXO PSBT input for the anchor. No signature — the caller signs
    // downstream, and for the script-path case it also assembles the final witness, so all
    // we owe it here is enough context to identify what is being spent.
    let mut anchor_psbt_input = PsbtInput {
        witness_utxo: Some(anchor_txout.clone()),
        ..Default::default()
    };
    match &anchor {
        AnchorInfo::KeyPath { internal_key, .. } => {
            anchor_psbt_input.tap_internal_key = Some(*internal_key);
        }
        AnchorInfo::ScriptPath {
            leaf_script,
            control_block,
            ..
        } => {
            // Record the leaf under its control block so the PSBT is self-describing. The
            // downstream signer builds the witness from the same pair, but a populated
            // `tap_scripts` keeps the intermediate PSBT meaningful to anything inspecting it.
            anchor_psbt_input.tap_scripts.insert(
                control_block.clone(),
                (leaf_script.clone(), LeafVersion::TapScript),
            );
        }
    }

    let mut tx_builder = wallet.build_tx();
    tx_builder.version(3);
    tx_builder.fee_absolute(Amount::from_sat(selection.fee_sat));
    // Pin the locktime. BDK otherwise sets it to the current chain tip as an anti-fee-sniping
    // measure, and the funding inputs carry a sequence that enforces it. That makes the
    // locktime a live consensus field which changes on every new block, and so changes the
    // child's txid on every new block. A new block is also the most common reason to rebuild,
    // so that default works directly against the determinism this builder needs.
    tx_builder.nlocktime(bdk_wallet::bitcoin::absolute::LockTime::ZERO);
    // Order inputs and outputs deterministically rather than leaving the order to BDK.
    //
    // `TxOrdering::Untouched` preserves BDK's own iteration order over the manually-selected
    // set, and that order is not stable between calls. An unstable order gives the same child
    // a different txid on every rebuild. RBF then treats a same-rate rebuild as a replacement
    // and the incremental-fee rule rejects it, instead of the resubmission deduplicating
    // against the child that is already in the mempool.
    //
    // The signer finds the anchor by outpoint rather than by index, so the input order is free
    // to change. The child has one output today, but sort it on its own fields anyway: BDK
    // sorts with `sort_unstable_by`, so a comparator that returns `Equal` for everything does
    // not guarantee the original order if a second output is ever added.
    tx_builder.ordering(TxOrdering::Custom {
        input_sort: std::sync::Arc::new(|a, b| a.previous_output.cmp(&b.previous_output)),
        output_sort: std::sync::Arc::new(|a, b| {
            a.value
                .cmp(&b.value)
                .then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
        }),
    });
    // Funding inputs first, then the anchor. `add_foreign_utxo` rejects an outpoint that is
    // already present as a local input, so this order turns a duplicate into a loud error.
    // The reverse order overwrites the foreign entry without an error, and the anchor then
    // loses the spend data that the downstream signer needs.
    //
    // A funding input that the wallet counts as spent enters as a foreign input. Only a
    // `replacing` outpoint can be in that state: the prior child spends it in the wallet's
    // view. The replacement child conflicts with the prior child by construction (both
    // spend the anchor), so the re-spend is the intended RBF.
    for outpoint in &selection.funding {
        match tx_builder.add_utxo(*outpoint) {
            Ok(_) => {}
            Err(e) => {
                let Some((_, txout)) = replaced_txouts.iter().find(|(op, _)| op == outpoint) else {
                    return Err(NativeGeneralError::FundingUtxo(format!("{e:?}")));
                };
                tx_builder
                    .add_foreign_utxo(
                        *outpoint,
                        PsbtInput {
                            witness_utxo: Some(txout.clone()),
                            ..Default::default()
                        },
                        bdk_wallet::bitcoin::Weight::from_wu(TAPROOT_KEY_PATH_SAT_WEIGHT as u64),
                    )
                    .map_err(|e| NativeGeneralError::FundingUtxo(format!("{e:?}")))?;
            }
        }
    }
    tx_builder
        .add_foreign_utxo(
            anchor_outpoint,
            anchor_psbt_input,
            bdk_wallet::bitcoin::Weight::from_wu(anchor.satisfaction_weight() as u64),
        )
        .map_err(|e| NativeGeneralError::AnchorForeignUtxo(format!("{e:?}")))?;
    // Defence in depth. The selection invariant already leaves BDK nothing to add, because the
    // chosen inputs cover the fee, and BDK stops as soon as that is true.
    tx_builder.manually_selected_only();
    tx_builder.drain_to(drain_script);

    let psbt = tx_builder.finish()?;

    // The input count decides the size, and the input count is fixed above. A mismatch means
    // the fee no longer matches the shape it was computed for, which is a silent underpay or
    // overpay rather than a visible failure. Check it on every build, not only in debug.
    if psbt.unsigned_tx.input.len() != selection.funding.len() + 1 {
        return Err(NativeGeneralError::UnexpectedInputCount {
            expected: selection.funding.len() + 1,
            actual: psbt.unsigned_tx.input.len(),
        });
    }

    Ok(FundedPsbt { psbt })
}

/// The funding inputs chosen for a CPFP child, and the exact fee that this shape must pay.
struct FundingSelection {
    /// Wallet outpoints to spend, in addition to the anchor.
    funding: Vec<OutPoint>,
    /// Absolute fee, exact for the child that these inputs produce.
    fee_sat: u64,
}

/// Chooses the funding inputs for a CPFP child and computes the exact fee for the resulting
/// shape.
///
/// `fee_for` maps a child size in vbytes to the fee that lifts the package to the target rate.
/// Both the size and the fee depend on the number of funding inputs, so this walks the input
/// count upward and stops at the first count that works:
///
/// 1. Try no funding at all. When the anchor pays the fee and still leaves a spendable drain
///    output, the child is just the anchor input and the drain output. This is the payout-combined
///    shape.
/// 2. Otherwise add wallet UTXOs, largest first, and re-check after each one. Largest first keeps
///    the input count down, which keeps the child small and therefore the fee low.
///
/// Each candidate count gets its own fee, from its own exact size. Therefore the fee this
/// returns is exact for the shape it returns.
fn select_funding(
    wallet: &Wallet,
    exclude: &BTreeSet<OutPoint>,
    anchor_outpoint: OutPoint,
    anchor_value_sat: u64,
    anchor: &AnchorInfo,
    fee_for: &impl Fn(u64) -> u64,
    replaced: ReplacedChild<'_>,
) -> Result<FundingSelection, NativeGeneralError> {
    // The fee must also keep the child relayable on its own: at least 1 sat/vB over its own
    // vbytes. That is Core's default `minrelaytxfee`, a generic policy floor rather than a
    // BIP-431 rule. TRUC contributes topology limits and sibling eviction, not this floor.
    let fee_at = |n_funding: u64| -> u64 {
        let vbytes = child_vbytes_for(anchor, n_funding);
        // Three floors apply to the child fee. The target-rate fee prices the package. The
        // vbytes floor keeps the child relayable on its own (1 sat/vB, Core's default
        // `minrelaytxfee`). The replacement floor is BIP-125 rule 4: the new child must pay
        // the replaced child's fee plus the incremental relay fee over its own size, or
        // bitcoind rejects the replacement.
        let rbf_floor = replaced
            .fee
            .map_or(0, |prior| prior.to_sat().saturating_add(vbytes));
        fee_for(vbytes).max(vbytes).max(rbf_floor)
    };

    // Does the anchor alone cover its own fee and leave a spendable drain output?
    let fee_no_funding = fee_at(0);
    if anchor_value_sat >= fee_no_funding.saturating_add(DRAIN_DUST_SAT) {
        return Ok(FundingSelection {
            funding: Vec::new(),
            fee_sat: fee_no_funding,
        });
    }

    let tip = wallet.latest_checkpoint().height();
    let mut candidates: Vec<(OutPoint, u64)> = wallet
        .list_unspent()
        .filter(|utxo| {
            // Never the anchor. This filter is what keeps the anchor out of `add_utxos`, which
            // would otherwise overwrite the foreign-UTXO entry that carries the anchor's spend
            // data. It is load-bearing for `ParentTxCombined`: that payout output pays the
            // wallet's own receive script, so once the parent confirms and the wallet syncs,
            // the anchor really does appear in `list_unspent`.
            if utxo.outpoint == anchor_outpoint || exclude.contains(&utxo.outpoint) {
                return false;
            }
            is_spendable_funding(wallet, utxo, tip)
        })
        .map(|utxo| (utxo.outpoint, utxo.txout.value.to_sat()))
        .collect();
    // Add the prior child's funding inputs to the candidates explicitly. They do not come
    // through `list_unspent`: a sync between two bumps applies the mempool, and BDK then
    // counts them as spent by the prior child. They are still correct funding for the
    // replacement, because the new child conflicts with the prior one by construction
    // (both spend the anchor). Without this step, each rebuild after a sync consumes a
    // fresh funding set. A wallet with one suitable UTXO then deadlocks: the UTXO frees
    // only when a conflicting child replaces the prior one, and no such child can be
    // built without the UTXO.
    //
    // Each outpoint still has to satisfy what `is_spendable_funding` demands of ordinary
    // candidates: known to the wallet, confirmed, and not an immature coinbase. Its own
    // confirmation status comes from the funding transaction, not from the (unconfirmed)
    // prior child spending it.
    //
    // Known gap, accepted: this checks the funding tx's confirmation, not whether some
    // *other confirmed* tx already spent the outpoint. Such an outpoint produces a child
    // that Core rejects with missing-inputs, retried on the next trigger. Reaching that
    // state requires the lease bookkeeping to have failed first — normally a confirmed
    // spend of our funding means our child confirmed, which means the parent confirmed
    // and the driver dropped the entry.
    for &outpoint in replaced.inputs {
        if outpoint == anchor_outpoint
            || exclude.contains(&outpoint)
            || candidates.iter().any(|(op, _)| *op == outpoint)
        {
            continue;
        }
        let Some(wtx) = wallet.get_tx(outpoint.txid) else {
            continue;
        };
        let Some(confirmation_height) = wtx.chain_position.confirmation_height_upper_bound() else {
            continue;
        };
        let tx = &wtx.tx_node.tx;
        if tx.is_coinbase() && tip.saturating_sub(confirmation_height) + 1 < COINBASE_MATURITY {
            continue;
        }
        let Some(txout) = tx.output.get(outpoint.vout as usize) else {
            continue;
        };
        candidates.push((outpoint, txout.value.to_sat()));
    }
    // Largest first, then by outpoint so the choice is deterministic across calls. Determinism
    // matters for RBF: an unchanged fee target must rebuild the same child, not a random one.
    // Largest first also keeps the input count down, which matters for the size limit below.
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut funding = Vec::new();
    let mut funded_sat = anchor_value_sat;
    for (outpoint, value) in candidates {
        // Stop before the child breaks the TRUC size limit. BIP-431 caps a v3 transaction that
        // has an unconfirmed v3 ancestor at 1000 vB, and this child always has one: the parent.
        // A child past that limit cannot enter any mempool, so building it is worse than
        // reporting that the wallet cannot fund the bump.
        if child_vbytes_for(anchor, funding.len() as u64 + 1) > TRUC_CHILD_MAX_VBYTES {
            break;
        }
        funding.push(outpoint);
        funded_sat = funded_sat.saturating_add(value);
        let fee_sat = fee_at(funding.len() as u64);
        if funded_sat >= fee_sat.saturating_add(DRAIN_DUST_SAT) {
            return Ok(FundingSelection { funding, fee_sat });
        }
    }

    Err(NativeGeneralError::InsufficientFunding {
        available: funded_sat,
        needed: fee_at(funding.len() as u64).saturating_add(DRAIN_DUST_SAT),
    })
}

/// Whether `utxo` can fund a CPFP child at chain height `tip`.
///
/// Two conditions, both of which BDK used to apply on our behalf when it did the selecting:
///
/// * The output must be confirmed. The child already has one unconfirmed parent, the CPFP parent
///   itself. A second unconfirmed parent breaks the TRUC topology rule and the package is rejected.
/// * A coinbase output must be mature. Spending one before 100 confirmations is a consensus error,
///   and the bump would repeat it on every tick.
fn is_spendable_funding(wallet: &Wallet, utxo: &bdk_wallet::LocalOutput, tip: u32) -> bool {
    let Some(confirmation_height) = utxo.chain_position.confirmation_height_upper_bound() else {
        return false;
    };
    let is_coinbase = wallet
        .get_tx(utxo.outpoint.txid)
        .is_some_and(|tx| tx.tx_node.tx.is_coinbase());
    !(is_coinbase && tip.saturating_sub(confirmation_height) + 1 < COINBASE_MATURITY)
}

/// Dust threshold for the child's P2TR drain output. Below this the output is unspendable and
/// the transaction is nonstandard.
const DRAIN_DUST_SAT: u64 = 330;

/// BIP-431 caps a v3 transaction that has an unconfirmed v3 ancestor at this size. The CPFP
/// child always has such an ancestor, because the parent is what it exists to pay for.
const TRUC_CHILD_MAX_VBYTES: u64 = 1000;

/// Confirmations a coinbase output needs before it can be spent.
const COINBASE_MATURITY: u32 = 100;

/// Predicted signed vbytes of a CPFP child spending `anchor` plus `n_funding` key-path
/// wallet inputs, draining to a single P2TR output.
///
/// Derived rather than guessed, and exact for the layouts we build: non-witness bytes are
/// version (4) + input/output counts (1 + 1) + locktime (4) + 41 per input (36 outpoint +
/// 1 script-len + 4 sequence) + 43 for the P2TR output (8 value + 1 len + 34 script);
/// witness is the anchor's own satisfaction weight, [`TAPROOT_KEY_PATH_SAT_WEIGHT`] per
/// funding input, and 2 wu for the segwit marker/flag.
///
/// Being anchor-aware matters: a `MultiAnchor` script-path spend carries a leaf script and a
/// control block that grows with tree depth, so a fixed figure would under-estimate it and —
/// because the child pays an *absolute* fee — silently underpay the package on every bump.
/// `n_funding = 0` gives the canonical 111 vB for a 1-in/1-out key-path Taproot spend.
fn child_vbytes_for(anchor: &AnchorInfo, n_funding: u64) -> u64 {
    let non_witness_bytes = 4 + 1 + 1 + 4 + (1 + n_funding) * 41 + 43;
    let witness_wu =
        anchor.satisfaction_weight() as u64 + n_funding * TAPROOT_KEY_PATH_SAT_WEIGHT as u64 + 2;
    (non_witness_bytes * 4 + witness_wu).div_ceil(4)
}

/// Builds a v3 (TRUC) PSBT using BDK's transaction builder, with `outputs` as recipients,
/// optional explicit input selection, the given fee rate, and `exclude` skipped during
/// auto-selection.
fn build_v3_psbt(
    wallet: &mut Wallet,
    outputs: &[TxOut],
    explicit_inputs: Option<&[OutPoint]>,
    fee_rate: FeeRate,
    exclude: &[OutPoint],
) -> Result<Psbt, CreateTxError> {
    let exclude_set: BTreeSet<OutPoint> = exclude.iter().copied().collect();

    let mut tx_builder = wallet.build_tx();
    tx_builder.version(3);
    tx_builder.fee_rate(fee_rate);
    tx_builder.ordering(TxOrdering::Untouched);

    match explicit_inputs {
        Some(inputs) => {
            for outpoint in inputs {
                tx_builder
                    .add_utxo(*outpoint)
                    .map_err(|_| CreateTxError::UnknownUtxo)?;
            }
            tx_builder.manually_selected_only();
        }
        None => {
            tx_builder.unspendable(exclude_set.into_iter().collect());
        }
    }

    for output in outputs {
        tx_builder.add_recipient(output.script_pubkey.clone(), output.value);
    }

    tx_builder.finish()
}

#[cfg(test)]
pub(super) mod tests {
    use bdk_wallet::{
        bitcoin::{
            absolute, hashes::Hash, opcodes, script, secp256k1::Secp256k1, taproot::TaprootBuilder,
            transaction::Version, Address, Amount, OutPoint, Transaction, TxIn, TxOut, Txid,
            Witness, XOnlyPublicKey,
        },
        test_utils::{get_funded_wallet_single, get_test_tr_single_sig},
    };

    use super::*;
    use crate::general::AnchorInfo;

    /// Builds a `MultiAnchor`-shaped Taproot output: one `<pubkey> OP_CHECKSIG` leaf per
    /// watchtower over a balanced tree. Returns the [`AnchorInfo::ScriptPath`] for the first
    /// leaf plus the resulting `script_pubkey`, so a parent can actually carry the output.
    fn script_path_anchor(n_watchtowers: usize) -> (AnchorInfo, ScriptBuf) {
        let secp = Secp256k1::new();
        let leaves: Vec<ScriptBuf> = (0..n_watchtowers)
            .map(|i| {
                let key = xonly_from_scalar(i as u8 + 2);
                script::Builder::new()
                    .push_slice(key.serialize())
                    .push_opcode(opcodes::all::OP_CHECKSIG)
                    .into_script()
            })
            .collect();
        let builder =
            TaprootBuilder::with_huffman_tree(leaves.iter().map(|s| (1u32, s.clone()))).unwrap();
        let internal_key = xonly_from_scalar(99);
        let spend_info = builder.finalize(&secp, internal_key).unwrap();
        let control_block = spend_info
            .control_block(&(leaves[0].clone(), LeafVersion::TapScript))
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, internal_key, spend_info.merkle_root());
        (
            AnchorInfo::ScriptPath {
                vout: 0,
                leaf_script: leaves[0].clone(),
                control_block,
            },
            spk,
        )
    }

    /// A v3 parent whose single output pays `script_pubkey`.
    fn parent_with_script_pubkey(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
        Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([9u8; 32]),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value,
                script_pubkey,
            }],
        }
    }

    /// Measures what `tx` will actually weigh once signed, by attaching witnesses of the real
    /// shape and letting rust-bitcoin serialize it. The anchor input is found by outpoint,
    /// because the builder sorts its inputs and the anchor is not necessarily first. A
    /// script-path anchor gets `[sig, leaf, control_block]`; every other input, and a key-path
    /// anchor, gets a bare signature.
    ///
    /// This is the independent oracle for the size predictor — it shares no arithmetic with
    /// `child_vbytes_for`, so a bug in the predictor cannot hide behind it.
    fn signed_vsize_of(tx: &Transaction, anchor: &AnchorInfo, anchor_outpoint: OutPoint) -> usize {
        let mut signed = tx.clone();
        for input in &mut signed.input {
            let mut witness = Witness::new();
            match anchor {
                AnchorInfo::ScriptPath {
                    leaf_script,
                    control_block,
                    ..
                } if input.previous_output == anchor_outpoint => {
                    witness.push([0u8; 64]);
                    witness.push(leaf_script.as_bytes());
                    witness.push(control_block.serialize());
                }
                // Key-path anchor and every wallet funding input: a bare 64-byte Schnorr
                // signature (TapSighashType::Default omits the trailing sighash byte).
                _ => witness.push([0u8; 64]),
            }
            input.witness = witness;
        }
        signed.vsize()
    }

    fn xonly_from_scalar(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = bdk_wallet::bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32])
            .expect("valid scalar");
        sk.x_only_public_key(&secp).0
    }

    /// Constructs an XOnlyPublicKey from a deterministic non-zero scalar, for tests that need
    /// "some valid key, doesn't matter which".
    pub(super) fn fake_anchor_key() -> XOnlyPublicKey {
        let bytes = [3u8; 32];
        let sk = bdk_wallet::bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
        let secp = Secp256k1::new();
        let (xonly, _) = bdk_wallet::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .x_only_public_key();
        xonly
    }

    /// Builds a synthetic "parent" tx whose `vout = anchor_vout` is a keyed-Taproot anchor
    /// at `anchor_value`. The rest of the outputs are dummies, so the parent looks like a
    /// real bridge tx that has an anchor at a known position.
    pub(super) fn parent_with_anchor(
        anchor_internal_key: XOnlyPublicKey,
        anchor_vout: u32,
        anchor_value: Amount,
    ) -> Transaction {
        let secp = Secp256k1::new();
        let anchor_addr = Address::p2tr(&secp, anchor_internal_key, None, Network::Regtest);
        let anchor_txout = TxOut {
            value: anchor_value,
            script_pubkey: anchor_addr.script_pubkey(),
        };
        let mut outputs = Vec::new();
        let dummy_addr = Address::p2tr(&secp, fake_anchor_key(), None, Network::Regtest);
        for _ in 0..anchor_vout {
            outputs.push(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: dummy_addr.script_pubkey(),
            });
        }
        outputs.push(anchor_txout);

        Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: outputs,
        }
    }

    /// A replacement child must pay at least the replaced child's fee plus 1 sat/vB over
    /// its own size (BIP-125 rule 4). At an unchanged target the rate-based fee equals the
    /// prior fee, which rule 4 rejects. With `prior_child_fee` set, the builder lifts the
    /// fee to the floor, and the increment equals the child's vbytes.
    #[tokio::test]
    async fn a_replacement_child_pays_the_rbf_floor() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };
        let target = FeeRate::from_sat_per_vb(5).unwrap();

        let first = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor.clone(),
            target,
            &[],
            ReplacedChild::default(),
        )
        .expect("first child must build");
        let first_fee = first.psbt.fee().expect("witness_utxo on every input");
        let child_vbytes = child_vbytes_for(&anchor, first.psbt.unsigned_tx.input.len() as u64 - 1);

        let replacement = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            target,
            &[],
            ReplacedChild {
                inputs: &[],
                fee: Some(first_fee),
            },
        )
        .expect("replacement must build");
        let replacement_fee = replacement.psbt.fee().expect("witness_utxo on every input");
        assert_eq!(
            replacement_fee,
            first_fee + Amount::from_sat(child_vbytes),
            "replacement fee must sit exactly on the BIP-125 floor"
        );
    }

    /// A rebuild after the wallet has observed the prior child must be able to re-spend
    /// that child's own funding inputs.
    ///
    /// Production syncs apply the mempool (`apply_unconfirmed_txs`), after which BDK counts
    /// the prior child's funding as spent: `list_unspent` stops offering it and `add_utxo`
    /// refuses it. The replacement child conflicts with the prior one by construction (both
    /// spend the anchor), so re-spending that funding is plain RBF — without the `replacing`
    /// override, every rebuild-after-sync burns a fresh UTXO, and a wallet whose only
    /// suitable UTXO is tied up in the prior child deadlocks entirely. This test pins both
    /// halves: the deadlock exists without `replacing`, and `replacing` resolves it onto
    /// the exact same funding set.
    #[tokio::test]
    async fn a_rebuild_after_sync_reuses_the_prior_childs_funding() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };
        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };

        let first = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor.clone(),
            FeeRate::from_sat_per_vb(5).unwrap(),
            &[],
            ReplacedChild::default(),
        )
        .expect("first child must build");
        let prior_funding: Vec<OutPoint> = first
            .psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| i.previous_output)
            .filter(|op| *op != anchor_outpoint)
            .collect();
        assert!(
            !prior_funding.is_empty(),
            "test needs a child that draws wallet funding"
        );

        // The sync between two bumps: the wallet observes its own unconfirmed child.
        wallet.apply_unconfirmed_txs(vec![(first.psbt.unsigned_tx.clone(), 100u64)]);

        // Without the override the funded wallet's only UTXO is gone and the rebuild
        // deadlocks. This is the bug, pinned.
        let starved = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor.clone(),
            FeeRate::from_sat_per_vb(8).unwrap(),
            &[],
            ReplacedChild::default(),
        );
        assert!(
            matches!(starved, Err(NativeGeneralError::InsufficientFunding { .. })),
            "without `replacing` the synced wallet must starve, got {starved:?}"
        );

        // With the override the rebuild re-spends exactly the prior funding set.
        let rebuilt = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            FeeRate::from_sat_per_vb(8).unwrap(),
            &[],
            ReplacedChild {
                inputs: &prior_funding,
                fee: None,
            },
        )
        .expect("rebuild with `replacing` must succeed");
        let rebuilt_funding: Vec<OutPoint> = rebuilt
            .psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| i.previous_output)
            .filter(|op| *op != anchor_outpoint)
            .collect();
        assert_eq!(
            rebuilt_funding, prior_funding,
            "the replacement must fund from the prior child's own inputs"
        );
        // The foreign-input route must still carry what the downstream signer needs.
        for (i, input) in rebuilt.psbt.inputs.iter().enumerate() {
            assert!(
                input.witness_utxo.is_some(),
                "psbt input {i} lacks witness_utxo"
            );
        }
    }

    /// The payout-combined shape: the foreign "anchor" is a full-value payout output that
    /// can pay for the child on its own. Pins the two properties the e2e caught a
    /// regression in: (a) the no-funding arm is selected (single input — the payout), and
    /// (b) the child pays the exact absolute package make-up fee, independent of the size
    /// BDK realizes (a per-vB-rate regression pays less on the smaller-than-estimate child
    /// and undershoots the package target).
    #[tokio::test]
    async fn payout_combined_child_pays_absolute_package_fee_without_funding_input() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(1_000_000));
        let parent_fee = Amount::from_sat(500);
        let target = FeeRate::from_sat_per_vb(20).unwrap();
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };
        // Pinned literal, NOT `child_vbytes_for(..)` — calling the implementation here would
        // re-derive any error in the size predictor and the assertion below would hold for a
        // wrong constant. 111 vB is the canonical 1-in/1-out Taproot key-path spend.
        let expected_child_vb = 111;
        assert_eq!(
            child_vbytes_for(&anchor, 0),
            expected_child_vb,
            "size predictor drifted from the canonical 1-in/1-out key-path Taproot vsize"
        );

        let funded = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            parent_fee,
            anchor.clone(),
            target,
            &[],
            ReplacedChild::default(),
        )
        .expect("payout-combined child must build");

        assert_eq!(
            funded.psbt.unsigned_tx.input.len(),
            1,
            "payout value covers the fee: the child must spend only the payout output"
        );
        // Cross-check the pinned 111 against a real serialization of the built child.
        assert_eq!(
            signed_vsize_of(
                &funded.psbt.unsigned_tx,
                &anchor,
                OutPoint {
                    txid: parent.compute_txid(),
                    vout: 0
                },
            ) as u64,
            expected_child_vb,
            "realized signed child vsize disagrees with the pinned constant"
        );
        let parent_vb = parent.vsize() as u64;
        // Independent oracle: 20 sat/vB × package vbytes − parent fee, in plain integer
        // math (exact for whole sat/vB targets).
        let expected_fee = 20 * (parent_vb + expected_child_vb) - parent_fee.to_sat();
        assert_eq!(
            funded
                .psbt
                .fee()
                .expect("witness_utxo on every input")
                .to_sat(),
            expected_fee,
            "child must pay the exact absolute package make-up fee"
        );
    }

    /// BDK's coin selection returns early — without ever consulting wallet UTXOs — once the
    /// already-selected value exceeds the target fee. An anchor worth slightly more than the
    /// fee therefore yields a below-dust drain output and the whole build fails with
    /// `InsufficientFunds`, despite a well-funded wallet. `InferGeneralPayout` makes this
    /// reachable in production: it uses BDK's own change output as the CPFP anchor, and change
    /// values are arbitrary.
    ///
    /// Sweeps anchor values across the whole region where the shape flips, at several targets.
    /// Low targets matter most: the gap between the no-funding and funded fees is
    /// `(169 − 111) × target` sat, so below roughly 6 sat/vB it is narrower than the dust
    /// threshold and the shape threshold alone cannot keep selection off the failing path.
    #[tokio::test]
    async fn anchor_value_near_the_fee_boundary_still_builds() {
        let anchor_key = fake_anchor_key();
        let parent_fee = Amount::from_sat(100);
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };
        let probe = parent_with_anchor(anchor_key, 0, Amount::from_sat(1));
        let parent_vb = probe.vsize() as u64;

        let cases: Vec<(u64, u64)> = [2u64, 3, 5, 10, 20]
            .into_iter()
            .flat_map(|target_sat_vb| {
                let fee_at = |vb: u64| target_sat_vb * (parent_vb + vb) - parent_fee.to_sat();
                let lo = fee_at(111).saturating_sub(400);
                let hi = fee_at(169) + 700;
                // Step 29 (coprime with the 330-sat dust threshold) so the sweep can't alias
                // past a narrow failing band.
                (lo..=hi)
                    .step_by(29)
                    .map(move |av| (target_sat_vb, av))
                    .collect::<Vec<_>>()
            })
            .collect();

        for (target_sat_vb, anchor_value) in cases {
            let target = FeeRate::from_sat_per_vb(target_sat_vb).unwrap();
            let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
            let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(anchor_value));
            let funded = build_cpfp_child_impl(
                &mut wallet,
                &parent,
                parent_fee,
                anchor.clone(),
                target,
                &[],
                ReplacedChild::default(),
            )
            .unwrap_or_else(|e| {
                panic!("target {target_sat_vb} sat/vB, anchor {anchor_value} sat: must build, got {e:?}")
            });

            // Whatever shape it picked, the drain output must be spendable.
            let drain = funded
                .psbt
                .unsigned_tx
                .output
                .first()
                .expect("child always has a drain output");
            assert!(
                drain.value.to_sat() >= DRAIN_DUST_SAT,
                "anchor {anchor_value} sat: drain {} below dust",
                drain.value
            );
        }
    }

    /// With an absolute fee, an under-estimated child size means the fixed fee is spread over
    /// more vbytes and the package pays BELOW target. A script-path (`MultiAnchor`) child is
    /// materially heavier than a key-path one — leaf script plus a control block that grows
    /// with tree depth — so a size predictor blind to anchor shape underpays every contest and
    /// bridge-proof-timeout bump. Assert the realized package rate holds at target for a range
    /// of watchtower counts.
    #[tokio::test]
    async fn script_path_anchor_package_meets_target_at_every_tree_depth() {
        let parent_fee = Amount::from_sat(500);
        let target_sat_vb = 20;
        let target = FeeRate::from_sat_per_vb(target_sat_vb).unwrap();

        for n_watchtowers in [2usize, 3, 5, 9, 16] {
            let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
            let (anchor, anchor_spk) = script_path_anchor(n_watchtowers);
            let parent = parent_with_script_pubkey(anchor_spk, Amount::from_sat(330));

            let funded = build_cpfp_child_impl(
                &mut wallet,
                &parent,
                parent_fee,
                anchor.clone(),
                target,
                &[],
                ReplacedChild::default(),
            )
            .unwrap_or_else(|e| panic!("{n_watchtowers} watchtowers must build, got {e:?}"));

            let child_fee = funded
                .psbt
                .fee()
                .expect("witness_utxo on every input")
                .to_sat();
            // Independent oracle: attach witnesses of the real shape and let rust-bitcoin's
            // own serializer measure the result. Deliberately NOT `child_vbytes_for` — using
            // the predictor here would make the assertion hold for any predictor, including a
            // wrong one.
            let child_vb = signed_vsize_of(
                &funded.psbt.unsigned_tx,
                &anchor,
                OutPoint {
                    txid: parent.compute_txid(),
                    vout: 0,
                },
            ) as u64;
            let pkg_fee = child_fee + parent_fee.to_sat();
            let pkg_vb = parent.vsize() as u64 + child_vb;

            // Exact, not merely sufficient. The funding inputs are chosen before the fee is
            // computed, so the shape that was priced is the shape that got built. The only
            // slack allowed is integer truncation, worth well under one sat per package.
            let required = target_sat_vb * pkg_vb;
            assert!(
                pkg_fee >= required,
                "{n_watchtowers} watchtowers: package pays {pkg_fee} sat over {pkg_vb} vB \
                 = {:.2} sat/vB, below the {target_sat_vb} sat/vB target",
                pkg_fee as f64 / pkg_vb as f64
            );
            assert!(
                pkg_fee <= required + 1,
                "{n_watchtowers} watchtowers: package pays {pkg_fee} sat against {required} \
                 required — more than rounding, so the priced shape is not the built shape"
            );
        }
    }

    /// A wallet of many tiny UTXOs must not produce an oversized child.
    ///
    /// BIP-431 caps a v3 transaction that has an unconfirmed v3 ancestor at 1000 vB, and this
    /// child always has one. Without a bound the selection keeps adding inputs, because each
    /// tiny UTXO contributes less than the fee that its own input costs. The result is a child
    /// that no mempool accepts, rebuilt on every tick.
    ///
    /// Reporting that the wallet cannot fund the bump is the honest outcome here.
    #[tokio::test]
    async fn tiny_utxos_do_not_produce_an_oversized_child() {
        use bdk_wallet::test_utils::receive_output_in_latest_block;

        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let big = wallet
            .list_unspent()
            .next()
            .expect("seeded wallet has one utxo")
            .outpoint;
        // Each of these is worth barely more than the 575 sat that one extra input costs at
        // 10 sat/vB. Therefore the selection does reach the fee eventually, but only after
        // about 24 inputs, by which point the child is roughly 1 491 vB.
        for i in 0..40u64 {
            receive_output_in_latest_block(&mut wallet, 650 + i);
        }

        let anchor_key = fake_anchor_key();
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));

        let result = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(308),
            anchor.clone(),
            FeeRate::from_sat_per_vb(10).unwrap(),
            &[big],
            ReplacedChild::default(),
        );

        match result {
            Err(NativeGeneralError::InsufficientFunding { .. }) => {}
            Err(other) => panic!("expected InsufficientFunding, got {other:?}"),
            Ok(funded) => {
                let vb = signed_vsize_of(
                    &funded.psbt.unsigned_tx,
                    &anchor,
                    OutPoint {
                        txid: parent.compute_txid(),
                        vout: 0,
                    },
                );
                panic!(
                    "built a {vb} vB child from {} inputs; TRUC rejects anything over \
                     {TRUC_CHILD_MAX_VBYTES} vB with an unconfirmed parent",
                    funded.psbt.unsigned_tx.input.len()
                );
            }
        }
    }

    /// The review that prompted deterministic selection noted that every existing test used a
    /// single-UTXO wallet, so no child ever had more than one funding input, and the
    /// multi-input fee math was never exercised. Build a wallet of small UTXOs so the child
    /// must draw several, and assert the package still lands exactly on target.
    #[tokio::test]
    async fn multi_input_funding_pays_the_exact_package_fee() {
        use bdk_wallet::test_utils::receive_output_in_latest_block;

        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let big = wallet
            .list_unspent()
            .next()
            .expect("seeded wallet has one utxo")
            .outpoint;
        // Distinct values, because two outputs of the same value to the same address produce
        // the same txid and therefore collapse into a single UTXO.
        for i in 0..8u64 {
            receive_output_in_latest_block(&mut wallet, 5_000 + i * 137);
        }

        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let parent_fee = Amount::from_sat(308);
        let target_sat_vb = 50;
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };

        // Exclude the single large seeded UTXO, forcing the builder onto the small ones.
        let funded = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            parent_fee,
            anchor.clone(),
            FeeRate::from_sat_per_vb(target_sat_vb).unwrap(),
            &[big],
            ReplacedChild::default(),
        )
        .expect("multi-input child must build");

        let n_funding = funded.psbt.unsigned_tx.input.len() - 1;
        assert!(
            n_funding >= 2,
            "test is pointless unless several funding inputs are drawn; got {n_funding}"
        );

        let child_fee = funded
            .psbt
            .fee()
            .expect("witness_utxo on every input")
            .to_sat();
        let child_vb = signed_vsize_of(
            &funded.psbt.unsigned_tx,
            &anchor,
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
        ) as u64;
        let pkg_fee = child_fee + parent_fee.to_sat();
        let pkg_vb = parent.vsize() as u64 + child_vb;
        let required = target_sat_vb * pkg_vb;

        assert!(
            pkg_fee >= required && pkg_fee <= required + 1,
            "{n_funding} funding inputs: package pays {pkg_fee} sat over {pkg_vb} vB, \
             required {required} sat at {target_sat_vb} sat/vB"
        );
    }

    #[tokio::test]
    async fn happy_path_emits_psbt_with_anchor_and_funding() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };

        let funded = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            FeeRate::from_sat_per_vb(10).unwrap(),
            &[],
            ReplacedChild::default(),
        )
        .expect("happy-path build_cpfp_child must succeed");

        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };
        let psbt = &funded.psbt;

        // Anchor must be present as an input with witness_utxo + tap_internal_key, unsigned.
        let anchor_input_idx = psbt
            .unsigned_tx
            .input
            .iter()
            .position(|i| i.previous_output == anchor_outpoint)
            .expect("anchor outpoint must appear as an input");
        let anchor_psbt_input = &psbt.inputs[anchor_input_idx];
        assert!(anchor_psbt_input.witness_utxo.is_some());
        assert_eq!(anchor_psbt_input.tap_internal_key, Some(anchor_key));
        assert!(
            anchor_psbt_input.tap_key_sig.is_none(),
            "anchor must not be signed by the backend"
        );

        // At least one funding input must exist (the wallet's contribution).
        assert!(psbt.unsigned_tx.input.len() >= 2);

        // `spent()` (derived from psbt.unsigned_tx) includes EVERY input — including the
        // anchor. The caller is responsible for filtering anchor outpoints out of the lease
        // set when bookkeeping is anchor-aware (the OperatorWallet composer does that via
        // its release/lease cycle around build_cpfp_child).
        let spent = funded.spent();
        assert!(
            spent.contains(&anchor_outpoint),
            "spent() reports every input including the foreign anchor"
        );
        assert!(
            spent.iter().any(|op| *op != anchor_outpoint),
            "must report at least one wallet input as spent"
        );

        // The child must be v3.
        assert_eq!(psbt.unsigned_tx.version, Version(3));
    }

    #[tokio::test]
    async fn anchor_vout_out_of_range_errors() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        // Parent has 1 output (vout 0). Asking for anchor at vout 5 is out of range.
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let anchor = AnchorInfo::KeyPath {
            vout: 5,
            internal_key: anchor_key,
        };

        let err = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            FeeRate::from_sat_per_vb(10).unwrap(),
            &[],
            ReplacedChild::default(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            NativeGeneralError::AnchorVoutOutOfRange { vout: 5, .. }
        ));
    }

    #[tokio::test]
    async fn anchor_at_non_zero_vout_resolves_correctly() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 2, Amount::from_sat(330));
        let anchor = AnchorInfo::KeyPath {
            vout: 2,
            internal_key: anchor_key,
        };

        let funded = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            FeeRate::from_sat_per_vb(5).unwrap(),
            &[],
            ReplacedChild::default(),
        )
        .expect("non-zero-vout anchor must work");

        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: 2,
        };
        assert!(funded
            .psbt
            .unsigned_tx
            .input
            .iter()
            .any(|i| i.previous_output == anchor_outpoint));
    }
}

#[cfg(test)]
mod determinism {
    use bdk_wallet::{
        bitcoin::{Amount, FeeRate},
        test_utils::{
            get_funded_wallet_single, get_test_tr_single_sig, receive_output_in_latest_block,
        },
    };

    use super::{build_cpfp_child_impl, tests::*};
    use crate::general::{AnchorInfo, ReplacedChild};

    /// The same request must always produce the same child.
    ///
    /// This is not cosmetic. A reactive bump rebuilds the child at an unchanged fee target, and
    /// relies on that rebuild being byte-identical: the resubmission then deduplicates against
    /// the child already in the mempool. A child whose txid moves between rebuilds is instead
    /// treated as an RBF replacement and rejected by the incremental-fee rule.
    ///
    /// Two sources of instability were found here and both are now closed. Coin selection ran
    /// under a fresh `thread_rng` per build, which an earlier revision inherited from letting
    /// BDK select. Input order also came from BDK's iteration over its selected set, which is
    /// unstable between calls even when the set is identical.
    #[tokio::test]
    async fn repeated_builds_produce_an_identical_child() {
        let anchor_key = fake_anchor_key();
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));

        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..40 {
            let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
            for i in 0..6u64 {
                receive_output_in_latest_block(&mut wallet, 5_030 + i * 91);
            }
            let funded = build_cpfp_child_impl(
                &mut wallet,
                &parent,
                Amount::from_sat(308),
                anchor.clone(),
                FeeRate::from_sat_per_vb(20).unwrap(),
                &[],
                ReplacedChild::default(),
            )
            .expect("every build must succeed, not a random subset of them");
            seen.insert(funded.psbt.unsigned_tx.compute_txid());
        }

        assert_eq!(
            seen.len(),
            1,
            "40 identical requests produced {} different children",
            seen.len()
        );
    }

    /// A new block must not change the child.
    ///
    /// BDK sets nLockTime to the chain tip by default, as an anti-fee-sniping measure, and the
    /// funding inputs carry a sequence that enforces it. That makes the locktime a live
    /// consensus field which moves with every block, so the txid moves too.
    ///
    /// A new block is the most common reason to rebuild the child. If the txid moved on every
    /// block, then the most common reactive path would always produce a conflicting
    /// replacement at an unchanged fee rate, which the incremental-fee rule rejects.
    #[tokio::test]
    async fn a_new_block_does_not_change_the_child() {
        use bdk_wallet::{
            bitcoin::{hashes::Hash, BlockHash},
            chain::BlockId,
            test_utils::insert_checkpoint,
        };

        let anchor_key = fake_anchor_key();
        let anchor = AnchorInfo::KeyPath {
            vout: 0,
            internal_key: anchor_key,
        };
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));

        let build = |wallet: &mut bdk_wallet::Wallet| {
            build_cpfp_child_impl(
                wallet,
                &parent,
                Amount::from_sat(308),
                anchor.clone(),
                FeeRate::from_sat_per_vb(20).unwrap(),
                &[],
                ReplacedChild::default(),
            )
            .expect("child must build")
            .psbt
            .unsigned_tx
            .compute_txid()
        };

        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let before = build(&mut wallet);

        let tip = wallet.latest_checkpoint().height();
        insert_checkpoint(
            &mut wallet,
            BlockId {
                height: tip + 1,
                hash: BlockHash::all_zeros(),
            },
        );
        let after = build(&mut wallet);

        assert_eq!(
            before, after,
            "the child's txid changed when a block arrived, so a same-rate rebuild will \
             conflict with the child already in the mempool instead of deduplicating"
        );
    }
}
