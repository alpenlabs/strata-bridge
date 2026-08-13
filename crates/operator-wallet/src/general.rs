//! The [`GeneralWallet`] trait — abstraction over the operator's general-purpose funds
//! (the wallet that fronts payments, pays CPFP fees, and tops up other internal pools).
//! The trait isolates the surface that genuinely varies between backends; concrete
//! implementations live in submodules.
//!
//! Everything that doesn't vary between backends — leasing, the reserved wallet, anchor
//! filtering, cross-wallet transaction construction — lives on the composer
//! [`crate::OperatorWallet<G>`] that wraps a `GeneralWallet`.

pub mod native;

use std::error::Error as StdError;

use bdk_wallet::{
    bitcoin::{
        taproot::ControlBlock, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction, TxOut,
        XOnlyPublicKey,
    },
    chain::ChainPosition,
};

/// Metadata about the Taproot anchor that the CPFP child will spend.
///
/// Carried into [`GeneralWallet::build_cpfp_child`] so the backend can populate the PSBT input
/// without having to recover the spend data from the parent's anchor `script_pubkey` (which is
/// impossible — Taproot output keys are tweaked and commit to the script tree).
///
/// The bridge has two anchor shapes and they are spent differently:
///
/// * Most transactions carry a `KeyedAnchor` — a bare key-path output with no script tree, spent
///   with a single BIP-341 tap-tweaked signature.
/// * `contest` and `bridge_proof_timeout` carry a `MultiAnchor` — a script tree with one
///   `<watchtower_pubkey> OP_CHECKSIG` leaf per watchtower, so that any watchtower can bump them.
///   Spending one requires a script-path witness (signature + leaf script + control block) and an
///   *untweaked* signature.
#[derive(Debug, Clone)]
pub enum AnchorInfo {
    /// Key-path spend of a keyed-Taproot anchor with no script tree.
    KeyPath {
        /// Index of the anchor output in `parent.output`.
        vout: u32,
        /// Internal x-only key the anchor was constructed from. The output key is this internal
        /// key BIP-341-tweaked by an empty merkle root; the downstream signer needs the internal
        /// key (not the output key) to construct a key-path signature.
        internal_key: XOnlyPublicKey,
    },
    /// Script-path spend of a single leaf of a multi-leaf Taproot anchor.
    ScriptPath {
        /// Index of the anchor output in `parent.output`.
        vout: u32,
        /// The leaf script being satisfied.
        leaf_script: ScriptBuf,
        /// Control block proving `leaf_script`'s membership in the tree. Kept typed rather than
        /// pre-serialized so a malformed block cannot reach the chain: the only bytes we ever
        /// push are `ControlBlock::serialize`'s.
        control_block: ControlBlock,
    },
}

impl AnchorInfo {
    /// Index of the anchor output in the parent's `output` vector.
    pub const fn vout(&self) -> u32 {
        match self {
            Self::KeyPath { vout, .. } | Self::ScriptPath { vout, .. } => *vout,
        }
    }

    /// Estimated witness weight, in weight units, of satisfying this anchor input.
    ///
    /// BDK needs this to account for the foreign anchor input in the child's fee math. The
    /// key-path figure is the usual 1-byte item count plus a 65-byte signature push. The
    /// script-path figure is computed exactly rather than estimated, because the caller already
    /// holds the real leaf script and control block — a MultiAnchor's control block grows with
    /// tree depth (33 + 32×depth bytes), so a fixed guess would drift with the watchtower count.
    pub fn satisfaction_weight(&self) -> usize {
        match self {
            Self::KeyPath { .. } => TAPROOT_KEY_PATH_SAT_WEIGHT,
            Self::ScriptPath {
                leaf_script,
                control_block,
                ..
            } => {
                // Witness item count, then each element prefixed by its compact-size length.
                // A deep tree pushes the control block past 252 bytes (33 + 32×depth), at which
                // point the prefix is no longer a single byte — hence the varint helper rather
                // than a hardcoded 1.
                let elements = [64, leaf_script.len(), control_block.serialize().len()];
                1 + elements
                    .iter()
                    .map(|len| compact_size_len(*len) + len)
                    .sum::<usize>()
            }
        }
    }
}

/// Byte length of a Bitcoin compact-size integer encoding `n`.
const fn compact_size_len(n: usize) -> usize {
    if n < 253 {
        1
    } else if n <= 0xFFFF {
        3
    } else if n <= 0xFFFF_FFFF {
        5
    } else {
        9
    }
}

/// Estimated witness weight (in weight units) for a Taproot key-path spend: 1 byte witness
/// item count + 65 bytes for the Schnorr signature push.
pub(crate) const TAPROOT_KEY_PATH_SAT_WEIGHT: usize = 66;

/// Whether the parent output that a CPFP child spends belongs to this wallet.
///
/// A child always spends one output of its parent. For most parents that output is a CPFP
/// anchor keyed to a protocol key, and the wallet can never select it for another
/// transaction. For a parent that pays this operator, the child spends the payout output
/// instead, and the wallet can select that output once the parent confirms.
///
/// The composer reads this value to decide what the lease of the child covers. A foreign
/// output stays out of the lease, because a lease on an outpoint that the wallet does not own
/// records a claim it cannot act on. A wallet output enters the lease, because a concurrent
/// duty must not select an output that a live child already spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorOwnership {
    /// The output belongs to a protocol key. It stays out of the lease.
    Foreign,
    /// The output pays this wallet. It enters the lease.
    Wallet,
}

/// The prior CPFP child that a rebuild replaces via RBF.
///
/// The backend has two obligations toward the replaced child:
///
/// * Selection: `inputs` must stay selectable even when the backend's own view shows them as spent.
///   After the backend observes the prior child, they read as spent. Without this override, each
///   rebuild consumes a fresh funding set until no funding remains.
/// * Fee: when `fee` is known, the new child must pay at least `fee + 1 sat/vB × the new child's
///   vbytes` (BIP-125 rule 4). Below that floor, bitcoind rejects the replacement.
///
/// [`ReplacedChild::default`] means there is no prior child.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplacedChild<'a> {
    /// Funding outpoints of the prior child. Empty when there is no prior child.
    pub inputs: &'a [OutPoint],
    /// Absolute fee of the prior child, when known.
    pub fee: Option<Amount>,
}

/// A backend that manages the operator's general-purpose Bitcoin funds.
///
/// The trait is intentionally narrow: it covers UTXO discovery + signing + transaction
/// construction for the general wallet only. Lease bookkeeping, the reserved wallet, and
/// anchor handling live on the composer.
///
/// # Signing contract
///
/// A backend signs the inputs it has key material for. Inputs it leaves unsigned must
/// carry `witness_utxo` (and `tap_internal_key` for Taproot key-path) so the caller can
/// sign them downstream by whatever means it sees fit.
pub trait GeneralWallet: Send + Sync {
    /// Backend-specific error type.
    type Error: StdError + Send + Sync + 'static;

    /// Refreshes internal state from the underlying source. Idempotent.
    ///
    /// Takes `&mut self` because the typical native impl needs to mutate its BDK wallet
    /// state. Callers serialize via an outer lock; the trait doesn't impose interior
    /// mutability.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Returns the receive script for this wallet. Stable across calls for native backends;
    /// may rotate for backends that mint fresh deposit addresses per call.
    fn script_pubkey(&self) -> ScriptBuf;

    /// Returns every UTXO this wallet currently controls (confirmed and unconfirmed). The
    /// caller is responsible for filtering anchors, leases, and other domain-specific
    /// exclusions before requesting funding.
    fn list_utxos(&self) -> Vec<UtxoInfo>;

    /// Builds a v3 TRUC funding transaction and signs the inputs it has key material for.
    ///
    /// * `outputs` — recipient outputs to fund. Change (if any) is appended.
    /// * `explicit_inputs` — when `Some`, only these outpoints are used as inputs. When `None`, the
    ///   backend selects inputs from its spendable UTXO set, skipping `exclude`.
    /// * `fee_rate` — target sat-per-vbyte for the transaction itself.
    /// * `exclude` — outpoints the backend must not select (anchors, currently-leased outpoints,
    ///   etc.). Ignored when `explicit_inputs` is `Some`.
    ///
    /// Inputs the backend can sign are returned with their witnesses populated; the rest
    /// carry `witness_utxo` and `tap_internal_key` (for Taproot) so the caller can sign
    /// downstream.
    fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> impl std::future::Future<Output = Result<FundedPsbt, Self::Error>> + Send;

    /// Builds a v3 TRUC CPFP child for `parent`, spending the keyed-Taproot output described
    /// by `anchor` plus inputs drawn from this wallet to cover the child's share of the
    /// package fee.
    ///
    /// * `parent_fee` — caller-provided fee already paid by `parent`. Used together with parent
    ///   vbytes and `target_pkg_fee_rate` to compute the implied child fee. The caller always knows
    ///   this (it built or has access to the parent's prevouts), so the backend can stay I/O-free.
    /// * `anchor` — [`AnchorInfo`] identifying the foreign-key output to spend and its internal
    ///   key.
    /// * `target_pkg_fee_rate` — sat-per-vbyte target for the (parent, child) package as a whole.
    /// * `exclude` — fee-paying-input selection skips these outpoints. Used to avoid re-selecting
    ///   the funding input of a prior child being replaced via RBF.
    /// * `replaced` — the prior child that this build supersedes ([`ReplacedChild`]). See the type
    ///   documentation for the two obligations it carries.
    ///
    /// Per the trait-level signing contract, the anchor input is left unsigned with
    /// `witness_utxo` and `tap_internal_key` populated (the latter sourced from
    /// `anchor.internal_key`); inputs the backend holds key material for are signed.
    fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        target_pkg_fee_rate: FeeRate,
        exclude: &[OutPoint],
        replaced: ReplacedChild<'_>,
    ) -> impl std::future::Future<Output = Result<FundedPsbt, Self::Error>> + Send;
}

/// A funded PSBT returned by [`GeneralWallet`] funding operations.
#[derive(Debug, Clone)]
pub struct FundedPsbt {
    /// The funded PSBT. See the [`GeneralWallet`] signing contract for which inputs are
    /// signed vs. left for downstream signing.
    pub psbt: Psbt,
}

impl FundedPsbt {
    /// Returns the outpoints consumed as inputs to this PSBT, derived from
    /// `psbt.unsigned_tx`. Use this to lease the spent UTXOs against re-selection by
    /// concurrent callers.
    pub fn spent(&self) -> Vec<OutPoint> {
        self.psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect()
    }
}

/// A snapshot of a single UTXO controlled by a [`GeneralWallet`] (or, by convention, the
/// reserved wallet that the [`crate::OperatorWallet`] composer manages internally).
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

impl From<UtxoInfo> for TxOut {
    fn from(u: UtxoInfo) -> Self {
        Self {
            value: u.amount,
            script_pubkey: u.script_pubkey,
        }
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

/// Converts a BDK [`bdk_wallet::LocalOutput`] into a backend-neutral [`UtxoInfo`], computing
/// confirmations against `tip_height`. Shared between the native general-wallet backend and
/// the composer's reserved-wallet lookup since both are BDK-backed.
pub(crate) fn local_output_to_utxo_info(lo: &bdk_wallet::LocalOutput, tip_height: u32) -> UtxoInfo {
    let confirmations = match &lo.chain_position {
        ChainPosition::Confirmed { anchor, .. } => tip_height
            .saturating_sub(anchor.block_id.height)
            .saturating_add(1),
        ChainPosition::Unconfirmed { .. } => 0,
    };
    UtxoInfo {
        outpoint: lo.outpoint,
        amount: lo.txout.value,
        confirmations,
        script_pubkey: lo.txout.script_pubkey.clone(),
    }
}
