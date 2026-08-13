//! CPFP package construction + aggressive RBF for [`TxDriver`](crate::tx_driver::TxDriver).
//!
//! Bridge presigned transactions pay a protocol-floor fee rate (`fee::FEE_RATE = 2 sat/vB`).
//! On any non-trivial network load they get evicted from the mempool before confirming. To drive
//! them to confirmation we build a CPFP child that lifts the **package** (parent + child) fee
//! rate to whatever the fee source reports as the current target, RBF'ing the child on each
//! new block. Package fee accounting only — the child's per-vB rate can far exceed the operator's
//! `max_fee_rate` as long as the package average doesn't.
//!
//! ## Design summary
//!
//! - [`CpfpStrategy`] tells the driver how to derive a CPFP child for a given parent kind.
//! - [`CpfpContext`] bundles the dependencies the bump loop needs (wallet, fee source, anchor
//!   signer, max fee rate, package submitter).
//! - [`perform_bump`] is the single source of truth for the bump loop: it queries the fee source,
//!   builds the child via the wallet, signs the anchor input via the operator's secret service
//!   (through a caller-provided closure), and submits `[parent, child]` via
//!   [`submit_package`](crate::submitpackage::submit_package).
//! - Termination is driven by the parent confirming (the existing mempool-event branch in
//!   `TxDriver` notifies the wait-condition listener). The bump function itself is stateless per
//!   call — it carries the last-attempted rate and the lease on the last child's funding inputs
//!   through the [`CpfpHandle`] state owned by the driver.
//!
//! ## What's intentionally NOT here
//!
//! - This module does not own ZMQ subscriptions; that's the driver's job.
//! - This module does not retry on its own — each `perform_bump` is one attempt. The driver
//!   re-calls on the next trigger (mempool eviction or new block).
//! - This module does not escalate past `max_fee_rate`. Cap-and-warn per the operator's policy.

use std::{
    fmt::{self, Debug},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use bitcoin::{
    secp256k1::{schnorr::Signature, Message},
    sighash::{Prevouts, SighashCache},
    taproot::{ControlBlock, LeafVersion, TapLeafHash},
    Amount, FeeRate, OutPoint, Psbt, ScriptBuf, TapSighashType, Transaction, TxOut, Txid, Witness,
};
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::submitpackage::{self, SubmitPackageError};

/// Configures how the driver derives a CPFP child for a particular parent transaction.
///
/// Not `Copy`: [`Self::MultiAnchorBearing`] carries the leaf script and control block needed for
/// a script-path spend.
#[derive(Debug, Clone)]
pub enum CpfpStrategy {
    /// Parent carries a keyed-Taproot anchor at `parent.output[anchor_vout]`. The child is
    /// constructed via the wallet's CPFP-anchor pathway and spends the anchor + one funding
    /// input.
    AnchorBearing {
        /// Index of the anchor output on `parent`.
        anchor_vout: u32,
        /// The internal x-only key the anchor was constructed from. Passed through to the
        /// wallet so it can populate the PSBT's `tap_internal_key` for downstream signing.
        anchor_internal_key: bitcoin::XOnlyPublicKey,
        /// Caller-known fee already paid by `parent`. The wallet uses this together with
        /// parent vbytes and the package target to compute the implied child fee.
        parent_fee: Amount,
    },
    /// Parent has a spendable payout output keyed to an operator-controlled key
    /// (cooperative payout, uncontested payout, contested payout, counterproof nack,
    /// unstaking). The child consumes that output via the same `add_foreign_utxo`
    /// machinery used for `AnchorBearing` anchors — the payout outpoint is foreign to
    /// BDK at the time we build the child (the parent hasn't been broadcast yet; we
    /// submit `[parent, child]` as a v3 package), so it can't be auto-selected from the
    /// wallet's UTXO set.
    ///
    /// The bump loop signs the payout input via [`CpfpContext::wallet_input_signer`] —
    /// not [`CpfpContext::anchor_input_signer`] — because the operator's general-wallet
    /// signer holds the key (the bridge assumes payouts are keyed to the operator's
    /// `payout_descriptor`, which resolves to the general-wallet P2TR; see the doc on
    /// [`crate::cpfp::InputSigner`] for the dispatch table).
    ParentTxCombined {
        /// The payout outpoint that the child will spend.
        payout_outpoint: OutPoint,
        /// Caller-known fee already paid by `parent`.
        parent_fee: Amount,
    },
    /// Parent carries a multi-leaf Taproot anchor at `parent.output[anchor_vout]` — one
    /// `<watchtower_pubkey> OP_CHECKSIG` leaf per watchtower, so any watchtower can bump it.
    /// Used by `contest` and `bridge_proof_timeout`.
    ///
    /// Unlike [`Self::AnchorBearing`] this is a **script-path** spend: the witness is
    /// `[signature, leaf_script, control_block]` and the signature is *untweaked* (the leaf is
    /// satisfied directly, not the tweaked output key). The bump loop signs it via
    /// [`CpfpContext::multi_anchor_signer`], not [`CpfpContext::anchor_input_signer`].
    ///
    /// The caller supplies `leaf_script` and `control_block` because reconstructing them
    /// requires the graph's watchtower key set and our slot within it — knowledge that lives in
    /// the state machine, not here. `btc-tracker` deliberately stays free of any dependency on
    /// the connector types.
    MultiAnchorBearing {
        /// Index of the anchor output on `parent`.
        anchor_vout: u32,
        /// The leaf script this operator is entitled to satisfy.
        leaf_script: ScriptBuf,
        /// Control block proving `leaf_script`'s membership in the anchor's tree.
        control_block: ControlBlock,
        /// Caller-known fee already paid by `parent`.
        parent_fee: Amount,
    },
}

impl CpfpStrategy {
    /// Returns the `parent_fee` carried by every variant.
    pub const fn parent_fee(&self) -> Amount {
        match self {
            Self::AnchorBearing { parent_fee, .. }
            | Self::ParentTxCombined { parent_fee, .. }
            | Self::MultiAnchorBearing { parent_fee, .. } => *parent_fee,
        }
    }
}

/// Per-parent state the driver carries between bump attempts.
#[derive(Debug, Default, Clone)]
pub struct CpfpHandle {
    /// Lease on the funding inputs of the most recent child that the wallet built.
    ///
    /// The wallet frees the inputs when the last clone of this value drops. Every path that
    /// stops the bumps for a parent therefore frees the inputs by dropping the handle, and no
    /// path needs an explicit release call.
    ///
    /// The value is an [`Arc`] because the driver clones the handle to run a bump without the
    /// entries lock held. The clone keeps the lease alive for the length of the bump. The
    /// write-back that replaces the handle then drops the last clone of the superseded lease.
    pub last_child_lease: Option<Arc<dyn FundingLease>>,
    /// Package fee rate the driver last targeted. Used to skip noop bumps when the fee source
    /// hasn't moved upward.
    pub last_pkg_fee_rate: Option<FeeRate>,
    /// Txid of the child we last broadcast (for tracking / replacement). `None` before the
    /// first bump succeeds.
    pub last_child_txid: Option<Txid>,
    /// Absolute fee that the most recent child pays. BIP-125 rule 4 requires a
    /// replacement to pay the replaced fee plus the incremental relay fee over the
    /// replacement's own size. The builder floors the next child's fee at this value plus
    /// 1 sat/vB × the new child's vbytes. A small target rise then produces a valid
    /// replacement. Without the floor, bitcoind rejects each replacement until the target
    /// rises by a full package-rate step.
    pub last_child_fee: Option<Amount>,
}

/// Errors produced by [`perform_bump`].
#[derive(Debug, Error)]
pub enum CpfpError {
    /// The fee source lookup failed. The bump is skipped; the next trigger will retry.
    #[error("fee source: {0}")]
    FeeSource(String),
    /// The wallet rejected the child build (insufficient funds, anchor out of range, ...).
    #[error("wallet build_cpfp_child: {0}")]
    Wallet(String),
    /// The anchor input signer returned an error. The bump is skipped; the next trigger
    /// will retry. Per design, secret-service hiccups don't escalate from the bump loop.
    #[error("anchor signer: {0}")]
    AnchorSigner(String),
    /// A wallet funding-input signer returned an error. Treated the same as
    /// [`Self::AnchorSigner`] — skip + retry.
    #[error("wallet input signer: {0}")]
    WalletSigner(String),
    /// `submitpackage` returned a non-success outcome. Logged + bump skipped.
    #[error("submit_package: {0}")]
    SubmitPackage(#[from] SubmitPackageError),
    /// PSBT finalization failed — every input must be either signed (funding) or have a
    /// caller-provided signature (anchor) by the time we get here.
    #[error("psbt extract: {0}")]
    PsbtExtract(String),
}

impl CpfpError {
    /// Whether this failure is a lost race for a shared anchor rather than a fault.
    ///
    /// See [`SubmitPackageError::is_replacement_contention`]. Callers use it to keep expected
    /// contention out of the warning stream.
    pub fn is_replacement_contention(&self) -> bool {
        matches!(self, Self::SubmitPackage(e) if e.is_replacement_contention())
    }
}

/// Wallet outpoints that one CPFP child holds.
///
/// The wallet frees the outpoints when this value drops, so the driver keeps the value for
/// as long as the child can still enter a mempool. This is what removes the release call from
/// every path that stops the bumps for a parent.
///
/// The trait keeps `btc-tracker` free of a dependency on the wallet crate. The bridge
/// implements it in `bridge-exec` over the lease type of `operator-wallet`.
pub trait FundingLease: Send + Sync + Debug {
    /// The outpoints that this lease holds. The anchor input is not one of them, unless the
    /// output that the child spends belongs to the wallet.
    fn outpoints(&self) -> &[OutPoint];
}

/// A funded PSBT returned by a wallet handle in [`CpfpContext`].
#[derive(Debug, Clone)]
pub struct WalletFundedPsbt {
    /// The funded child PSBT. Wallet inputs are signed or unsigned per the backend (see
    /// the [`CpfpWallet`] PSBT-signing contract); the anchor input is always unsigned and
    /// carries `witness_utxo` plus `tap_internal_key` (key-path) or `tap_scripts`
    /// (script-path) describing what is being spent.
    pub psbt: Psbt,
    /// Holds the wallet outpoints that the child consumes.
    pub lease: Arc<dyn FundingLease>,
}

/// Trait the driver calls to build the next CPFP child.
///
/// Decouples [`crate::tx_driver::TxDriver`] from `operator-wallet` so this crate stays at the
/// bottom of the dependency graph. The actual wallet handle in `bridge-exec` implements this
/// trait against `Arc<RwLock<OperatorWallet<G>>>`.
///
/// # PSBT-signing contract
///
/// The returned PSBT may be fully unsigned, partially signed, or fully signed — whatever
/// the wallet backend produces. [`perform_bump`] inspects each PSBT input's
/// `final_script_witness` and only signs the ones still unsigned (anchor input via
/// [`CpfpContext::anchor_input_signer`], everything else via
/// [`CpfpContext::wallet_input_signer`]). Two patterns are supported:
///
/// - **Descriptor-only wallets** (e.g. `NativeGeneralWallet`): no key material in the wallet,
///   returned PSBT is fully unsigned, every input gets signed by the bump loop.
/// - **Create-and-sign backends** (e.g. Fireblocks): wallet selects UTXOs and signs the funding
///   inputs in one API call, returned PSBT has wallet inputs already signed and only the foreign
///   anchor input unsigned. The bump loop fills in the anchor signature.
///
/// Either way the bump loop never overwrites an existing witness — that contract is what
/// makes swapping the wallet backend a pure-trait-impl exercise.
///
/// **Signed inputs must be finalized**: the skip check inspects `final_script_witness`,
/// not `tap_key_sig` or `partial_sigs`. A backend that produces a partially-signed PSBT
/// with sigs in `tap_key_sig` but no `final_script_witness` will see the bump loop sign
/// over the top of those partials. Backends MUST finalize their signed inputs before
/// returning (i.e. produce `final_script_witness` directly).
pub trait CpfpWallet: Send + Sync + fmt::Debug {
    /// Builds (or rebuilds via RBF) a CPFP child for `parent` under `strategy`, targeting
    /// `target_pkg_fee_rate` on the (parent, child) package.
    ///
    /// `prior_child_fee` is the absolute fee of the child being replaced, when there is one.
    /// The wallet must floor the new child's fee at `prior_child_fee + 1 sat/vB × the new
    /// child's vbytes` (BIP-125 rule 4), or bitcoind rejects the replacement as paying
    /// insufficient incremental fee.
    ///
    /// `replacing` is the lease of a prior child that this rebuild supersedes. Input
    /// selection must keep its outpoints available, so that the replacement can spend them
    /// again. The lease stays valid across the call: a failed build leaves it with the same
    /// outpoints, and the driver drops it once the new child supersedes the old one.
    ///
    /// See the trait-level "PSBT-signing contract" for what the returned PSBT must look
    /// like with respect to per-input `final_script_witness`.
    fn build_cpfp_child(
        &self,
        parent: &Transaction,
        strategy: CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        replacing: Option<&dyn FundingLease>,
        prior_child_fee: Option<Amount>,
    ) -> impl std::future::Future<Output = Result<WalletFundedPsbt, String>> + Send;
}

/// Source of fee-rate estimates used to drive the package target. Defined in this crate
/// (rather than reusing a wallet- or executor-side abstraction) so `btc-tracker` stays at
/// the bottom of the dependency graph; callers implement it for their estimator of choice.
///
/// In production the live estimator is wrapped in a [`CachedFeeSource`] so the bump loop
/// reads from a hot atomic instead of hitting the network per call. The tracker refreshes
/// it in the background on `refresh_interval`.
pub trait CpfpFeeSource: Send + Sync + fmt::Debug {
    /// Returns the current sat/vB target for the next block.
    fn estimate(&self) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send;
}

/// Boxed future returned by an [`InputSigner`]; pinned + Send so it can fly across the
/// driver's tokio task boundary.
pub type InputSignFut =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Signature, String>> + Send>>;

/// Signs one BIP-341 key-path Taproot input by computing a Schnorr signature over the
/// caller-supplied sighash. Used by [`perform_bump`] in two distinct roles:
///
/// 1. As [`CpfpContext::anchor_input_signer`] — signs the anchor input of an `AnchorBearing` child
///    with the key the parent's anchor was constructed from. In the bridge this is the operator's
///    musig2-signer pubkey (the "btc key" from the operator table), which `KeyedAnchor::new` is fed
///    in `tx-graph::transactions::{claim,stake,unstaking_intent,counterproof,counterproof_ack}`.
///    Caveat: counterproof / counterproof_ack nominally key their anchors to a *watchtower* pubkey,
///    but today the bridge identifies watchtower keys with musig2 keys (see the comment in
///    `bin/strata-bridge/src/mode/services/operator_wallet.rs` near `watchtower_keys`); if the two
///    sets ever diverge, this signer + the matching [`crate::cpfp::CpfpStrategy`] inference layer
///    need to grow a per-anchor-kind dispatch.
///
/// 2. As [`CpfpContext::wallet_input_signer`] — signs every funding input the wallet selected. In
///    the bridge this is the operator's general-wallet pubkey (the `tr()` descriptor key of
///    `NativeGeneralWallet`), which holds the UTXOs the child consumes.
///
/// Both roles call `sign(digest, None)` on a `SchnorrSigner` (from `secret-service-proto`)
/// — the `None` tweak applies the BIP-341 tap-tweak with an empty merkle root, matching how
/// the corresponding outputs were constructed (keyed-Taproot, no script tree).
pub type InputSigner = Arc<dyn Fn(Message) -> InputSignFut + Send + Sync>;

/// A [`CpfpFeeSource`] that caches the most recent estimate in a shared atomic, refreshed in
/// the background by a tokio task at a configurable interval.
///
/// Wraps any underlying [`CpfpFeeSource`] (typically the live `bridge-exec::fees::FeeSource`
/// going to Bitcoin Core or mempool.space). Reads from the cache are constant-time —
/// `estimate()` returns the latest cached value without I/O, so the bump loop in
/// [`TxDriver`](crate::tx_driver::TxDriver) can poll it on a fast timer without rate-limiting
/// the underlying source.
///
/// ## Initialization semantics
///
/// [`CachedFeeSource::spawn`] performs the first refresh synchronously and returns an error
/// if it fails. This is intentional: the bridge cannot start CPFP-bumping if the fee source
/// is unreachable at boot. Subsequent refresh failures are logged but the prior cached value
/// is retained — a transient network blip doesn't blank the cache.
///
/// ## Drop behaviour
///
/// The background task is aborted when the `CachedFeeSource` is dropped. The task itself
/// runs an infinite loop; tokio's `JoinHandle::abort` cancels it cleanly. In tests this
/// ensures one test's tracker doesn't leak into the next.
pub struct CachedFeeSource {
    cached_sat_per_kwu: Arc<AtomicU64>,
    /// Monotonic-millis-since-spawn of the most recent successful refresh. Stored as
    /// milliseconds elapsed from a process-start anchor [`Instant`] so it fits in `u64`
    /// and avoids wall-clock skew. Inspected via [`Self::seconds_since_last_refresh`] —
    /// callers can use that to decide how much to trust the cached value when bumping.
    last_refresh_unix_ms: Arc<AtomicU64>,
    /// Anchor point for the `last_refresh_unix_ms` clock. Same instant for the duration
    /// of the [`CachedFeeSource`]'s lifetime.
    spawn_anchor: std::time::Instant,
    task: JoinHandle<()>,
}

impl Debug for CachedFeeSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kwu = self.cached_sat_per_kwu.load(Ordering::Relaxed);
        f.debug_struct("CachedFeeSource")
            .field("cached_sat_per_kwu", &kwu)
            .field(
                "seconds_since_last_refresh",
                &self.seconds_since_last_refresh(),
            )
            .field("task_finished", &self.task.is_finished())
            .finish()
    }
}

impl Drop for CachedFeeSource {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CachedFeeSource {
    /// Performs one initial refresh from `underlying`, spawns a background task that re-polls
    /// every `refresh_interval`, and returns a `CachedFeeSource` whose `estimate()` reads from
    /// the cached atomic.
    pub async fn spawn<U>(underlying: Arc<U>, refresh_interval: Duration) -> Result<Self, String>
    where
        U: CpfpFeeSource + 'static,
    {
        let spawn_anchor = std::time::Instant::now();
        let initial = underlying.estimate().await?;
        let cached_sat_per_kwu = Arc::new(AtomicU64::new(initial.to_sat_per_kwu()));
        // Stamp the initial refresh time so `seconds_since_last_refresh()` returns ~0 right
        // after `spawn()` returns; otherwise the AtomicU64 would still be 0 and the elapsed
        // calc would report the time since `spawn_anchor` instead.
        let initial_elapsed_ms = spawn_anchor.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let last_refresh_unix_ms = Arc::new(AtomicU64::new(initial_elapsed_ms));
        let cache_clone = cached_sat_per_kwu.clone();
        let last_refresh_clone = last_refresh_unix_ms.clone();
        let task = tokio::task::spawn(async move {
            let mut tick = tokio::time::interval(refresh_interval);
            // `interval` fires immediately on first tick; we already have the initial value so
            // burn that tick before entering the refresh loop.
            tick.tick().await;
            loop {
                tick.tick().await;
                match underlying.estimate().await {
                    Ok(rate) => {
                        cache_clone.store(rate.to_sat_per_kwu(), Ordering::Relaxed);
                        let elapsed =
                            spawn_anchor.elapsed().as_millis().min(u64::MAX as u128) as u64;
                        last_refresh_clone.store(elapsed, Ordering::Relaxed);
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "fee-rate refresh failed; retaining last cached value"
                        );
                    }
                }
            }
        });
        Ok(Self {
            cached_sat_per_kwu,
            last_refresh_unix_ms,
            spawn_anchor,
            task,
        })
    }

    /// Returns the most recently cached fee rate without I/O.
    pub fn current(&self) -> FeeRate {
        FeeRate::from_sat_per_kwu(self.cached_sat_per_kwu.load(Ordering::Relaxed))
    }

    /// Returns the number of seconds since the cache was last *successfully* refreshed.
    /// Returns 0 for the initial refresh in [`Self::spawn`]. Lets callers decide how much
    /// to trust the cached value — e.g., the bump loop could log a warning when the cache
    /// is older than several refresh intervals (indicating the underlying source has been
    /// failing).
    pub fn seconds_since_last_refresh(&self) -> u64 {
        let last_ms = self.last_refresh_unix_ms.load(Ordering::Relaxed);
        let now_ms = self
            .spawn_anchor
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        now_ms.saturating_sub(last_ms) / 1_000
    }
}

impl CpfpFeeSource for CachedFeeSource {
    /// Returns the cached value. Never returns `Err` — refresh failures are logged at the
    /// background task and the prior value is retained.
    fn estimate(&self) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send {
        let value = self.current();
        async move { Ok(value) }
    }
}

/// What already spends a CPFP anchor, if anything.
///
/// A `MultiAnchor` anchor is shared. Every watchtower of the graph holds a leaf on it, and
/// every one of them bumps the same output. The bump loop reads this state before it builds,
/// so that a watchtower which has already lost the anchor stops paying to lose it again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorSpendState {
    /// Nothing spends the anchor. This operator can bump.
    Unspent,
    /// A mempool transaction spends the anchor, and its package pays this rate.
    SpentInMempool {
        /// Txid of the spending child. The bump loop compares it against its own last
        /// child. A foreign spender means this operator's child lost the anchor, and the
        /// bump loop must release the child's funding leases. Our own spender means the
        /// leases must stay: a release lets a concurrent build double-spend the live
        /// child's funding and evict it.
        spender: Txid,
        /// Package fee rate the spending child's ancestor set pays.
        pkg_fee_rate: FeeRate,
    },
    /// A confirmed transaction spends the anchor. No child can improve the parent now.
    Confirmed,
}

/// The bitcoind mempool operations that the bump loop needs.
pub trait CpfpMempool: Send + Sync + fmt::Debug {
    /// Forwards to bitcoind's `submitpackage` RPC; returns the typed summary.
    fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> impl std::future::Future<
        Output = Result<submitpackage::SubmitPackageSummary, SubmitPackageError>,
    > + Send;

    /// Reports what already spends `anchor`.
    ///
    /// The bump loop calls this only for a shared anchor, and treats an error as
    /// [`AnchorSpendState::Unspent`]. A failed lookup must not stop a bump, because the
    /// submission itself is the authority on whether the package is acceptable.
    fn anchor_spend_state(
        &self,
        anchor: OutPoint,
    ) -> impl std::future::Future<Output = Result<AnchorSpendState, String>> + Send;
}

/// Zero-sized placeholder that implements every CPFP trait but panics if any method is ever
/// called. Used by [`crate::tx_driver::TxDriver::new`] (the no-CPFP path) to satisfy the
/// generic bounds on [`crate::tx_driver::TxDriver::with_cpfp`] when `cpfp_ctx` is `None`.
///
/// The driver task only invokes the trait methods when `cpfp_ctx.is_some()`, so the
/// `unreachable!()` arms are safe by construction.
#[derive(Debug, Clone, Copy)]
pub struct CpfpDisabled;

// The trait signatures use the explicit `-> impl Future + Send` form to express the `Send`
// bound on the returned future. The `async fn` desugaring infers `Send`-ness from the body —
// which for these unreachable placeholders is still `Send`, but mirroring the trait's
// signature shape keeps the impl visually paired with the trait definition. Suppress
// `manual_async_fn` on each impl below accordingly.
#[expect(clippy::manual_async_fn, reason = "mirror AFIT trait signature shape")]
impl CpfpWallet for CpfpDisabled {
    fn build_cpfp_child(
        &self,
        _parent: &Transaction,
        _strategy: CpfpStrategy,
        _target_pkg_fee_rate: FeeRate,
        _replacing: Option<&dyn FundingLease>,
        _prior_child_fee: Option<Amount>,
    ) -> impl std::future::Future<Output = Result<WalletFundedPsbt, String>> + Send {
        async { unreachable!("CpfpDisabled::build_cpfp_child should never be called") }
    }
}

#[expect(clippy::manual_async_fn, reason = "see CpfpWallet impl above")]
impl CpfpFeeSource for CpfpDisabled {
    fn estimate(&self) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send {
        async { unreachable!("CpfpDisabled::estimate should never be called") }
    }
}

#[expect(clippy::manual_async_fn, reason = "see CpfpWallet impl above")]
impl CpfpMempool for CpfpDisabled {
    fn submit_package(
        &self,
        _txs: &[Transaction],
    ) -> impl std::future::Future<
        Output = Result<submitpackage::SubmitPackageSummary, SubmitPackageError>,
    > + Send {
        async { unreachable!("CpfpDisabled::submit_package should never be called") }
    }

    fn anchor_spend_state(
        &self,
        _anchor: OutPoint,
    ) -> impl std::future::Future<Output = Result<AnchorSpendState, String>> + Send {
        async { unreachable!("CpfpDisabled::anchor_spend_state should never be called") }
    }
}

/// Bundle of dependencies the bump loop needs.
///
/// Owned by [`TxDriver`](crate::tx_driver::TxDriver) (inside the spawned task's closure) when
/// CPFP is enabled; passed by reference into [`perform_bump`]. Cheap to clone — every field
/// is either `Copy` or `Arc`-wrapped, so the manual [`Clone`] impl on this type doesn't
/// require `W: Clone`/`F: Clone`/`P: Clone` (the derived `Clone` would).
pub struct CpfpContext<W, F, P>
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    /// Wallet that constructs the child PSBT. The PSBT comes back **unsigned**: bridge
    /// wallets are descriptor-only (no key material in the BDK wallet), so the funding
    /// inputs must be signed downstream via [`Self::wallet_input_signer`].
    pub wallet: Arc<W>,
    /// Source of the current package fee-rate target.
    pub fee_source: Arc<F>,
    /// Signs the **anchor input** of `AnchorBearing` children — the foreign-key input
    /// that the parent's CPFP anchor pins to. Bound to the operator's musig2-signer
    /// pubkey in production (see [`InputSigner`] doc). Not called for `ParentTxCombined`.
    pub anchor_input_signer: InputSigner,
    /// Signs the **script-path anchor input** of [`CpfpStrategy::MultiAnchorBearing`] children
    /// (`contest`, `bridge_proof_timeout`).
    ///
    /// Distinct from [`Self::anchor_input_signer`] because a script-path spend satisfies the leaf
    /// directly: the signature must be made with the raw key, *not* BIP-341 tap-tweaked. In the
    /// bridge this is the operator's musig2 signer used untweaked — the same key and mode
    /// `publish_contest` already uses to sign the contest transaction's own input.
    pub multi_anchor_signer: InputSigner,
    /// Signs every **wallet-selected funding input** the child consumes. Bound to the
    /// operator's general-wallet-signer pubkey in production. Called once per non-anchor
    /// input by [`perform_bump`]; closure may be invoked sequentially many times, so it
    /// should be cheap to retain a strong reference to (typically just an `Arc` to the
    /// secret-service handle).
    pub wallet_input_signer: InputSigner,
    /// Cap on the package-level fee rate. The bump loop clamps the fee source's reported
    /// target to this and warns when clamping kicks in. Per design, exceeding this is an
    /// operator policy decision: we don't escalate.
    pub max_fee_rate: FeeRate,
    /// Submits `[parent, child]` packages via bitcoind. Wrapper around the
    /// [`submitpackage::submit_package`] helper.
    pub mempool: Arc<P>,
}

impl<W, F, P> Clone for CpfpContext<W, F, P>
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    fn clone(&self) -> Self {
        Self {
            wallet: self.wallet.clone(),
            fee_source: self.fee_source.clone(),
            anchor_input_signer: self.anchor_input_signer.clone(),
            multi_anchor_signer: self.multi_anchor_signer.clone(),
            wallet_input_signer: self.wallet_input_signer.clone(),
            max_fee_rate: self.max_fee_rate,
            mempool: self.mempool.clone(),
        }
    }
}

impl<W, F, P> Debug for CpfpContext<W, F, P>
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpfpContext")
            .field("wallet", &self.wallet)
            .field("fee_source", &self.fee_source)
            .field("anchor_input_signer", &"<closure>")
            .field("wallet_input_signer", &"<closure>")
            .field("max_fee_rate", &self.max_fee_rate)
            .field("mempool", &self.mempool)
            .finish()
    }
}

/// Why the bump loop is being invoked. Controls the `target ≤ last bump rate` skip:
/// eager bumps (after broadcasting a new parent) skip; trigger-driven bumps (new block,
/// timer tick, parent mempool eviction) **do not**, because they may be reacting to the
/// previous child being purged with no parent-side event to clue us in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BumpReason {
    /// First bump for a freshly-broadcast parent. Skip if the fee source hasn't moved
    /// above the last rate — the fresh parent's protocol-floor fee is already a baseline.
    NewJob,
    /// A new block arrived. Always (re)build the child to keep mempool presence even at
    /// the same fee rate.
    NewBlock,
    /// The shared CPFP refresh tick fired. Same policy as [`Self::NewBlock`].
    Tick,
    /// The driver observed the parent leaving the mempool (eviction event). Always
    /// (re)attempt to push the package back in.
    ParentEvicted,
}

impl BumpReason {
    /// Whether the bump should skip on `target ≤ last_pkg_fee_rate`. Eager (`NewJob`)
    /// bumps skip to avoid wasted RBF; reactive bumps always rebuild.
    pub const fn skip_on_same_rate(self) -> bool {
        matches!(self, Self::NewJob)
    }
}

/// Drives one CPFP bump attempt for `parent` under `strategy`.
///
/// Returns `Ok(true)` if a package was submitted, `Ok(false)` if the bump was skipped
/// (see the skip conditions below), and the error variants of [`CpfpError`] otherwise.
///
/// Same-rate calls are a no-op only for [`BumpReason::NewJob`]; reactive reasons
/// (block/tick/eviction) rebuild the child even at an unchanged target, because a child
/// evicted by a competing package is invisible to us — see step 4 below.
///
/// `handle.last_child_lease` takes the new lease as soon as the wallet hands back a funded
/// child, and not only on success. The handle must own the lease across the fallible steps
/// that follow. A drop at one of those steps frees inputs that a live child still spends.
/// `handle.last_pkg_fee_rate` and `handle.last_child_txid` describe what actually reached the
/// mempool, so those advance only on success.
///
/// ## Cap-and-warn at `max_fee_rate`
///
/// When the fee source reports above `ctx.max_fee_rate`, the target is clamped and a warning
/// is logged. The bump proceeds at the cap. If the fee source's target remains above the cap
/// on subsequent calls, this is steady-state — operator's `max_fee_rate` is the most they're
/// willing to pay.
///
/// ## Baseline skips
///
/// Two conditions mean the parent needs no child at all (both return `Ok(false)`):
/// - the fee source reports `≤ bridge_protocol_floor` — the presigned parent's protocol-floor fee
///   rate is already sufficient;
/// - the parent's own fee (`strategy.parent_fee()` over its vbytes) already meets the target — a
///   child cannot improve the package rate, it would only pay for its own vbytes.
pub async fn perform_bump<W, F, P>(
    ctx: &CpfpContext<W, F, P>,
    parent: &Transaction,
    strategy: CpfpStrategy,
    handle: &mut CpfpHandle,
    bridge_protocol_floor: FeeRate,
    reason: BumpReason,
) -> Result<bool, CpfpError>
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpMempool + 'static,
{
    let parent_txid = parent.compute_txid();

    // ── 1. Query the fee source ─────────────────────────────────────────────
    let estimated = ctx
        .fee_source
        .estimate()
        .await
        .map_err(CpfpError::FeeSource)?;

    // ── 2. Clamp to max_fee_rate, warn if clamping kicked in ────────────────
    let target = if estimated > ctx.max_fee_rate {
        warn!(
            %parent_txid,
            estimated = ?estimated,
            cap = ?ctx.max_fee_rate,
            "fee source target exceeds max_fee_rate; clamping to cap (operator policy)"
        );
        ctx.max_fee_rate
    } else {
        estimated
    };

    // ── 3. Baseline skips: parent already sufficient on its own ─────────────
    if target <= bridge_protocol_floor {
        // Quiet by default — this fires on every bump tick for every parent in a quiet
        // mempool. `trace!` so it's still recoverable with -vvv.
        tracing::trace!(
            %parent_txid,
            ?target,
            ?reason,
            "fee source target at or below protocol floor; skipping CPFP child"
        );
        return Ok(false);
    }
    // If the parent's own fee already clears the target, a child can't improve the
    // package rate — it would only pay for its own vbytes. Skipping here also avoids a
    // wallet corner: a child asked to cover nothing but itself can end up selecting no
    // funding input at all and failing on a below-dust drain output.
    let parent_vbytes = u64::try_from(parent.vsize()).expect("tx vsize fits in u64");
    if let Some(parent_target_fee) = target.fee_vb(parent_vbytes) {
        if strategy.parent_fee() >= parent_target_fee {
            tracing::trace!(
                %parent_txid,
                ?target,
                parent_fee = %strategy.parent_fee(),
                parent_vbytes,
                ?reason,
                "parent fee alone meets target; skipping CPFP child"
            );
            return Ok(false);
        }
    }

    // ── 4. Skip if we already bumped at this rate (eager only) ──────────────
    //
    // Reactive bumps (new block / tick / parent eviction) DO rebuild at the same rate:
    // the previous child may have been silently evicted from the mempool by a competing
    // replacement, and the only signal we get is the absence of confirmation. A same-rate
    // resubmission either dedups against the still-present child (`txn-already-in-mempool`
    // is fine inside `submitpackage`) or, if the rebuilt child differs, gets rejected by
    // the BIP-125 incremental-fee rule — a logged, harmless failure. We accept that noise
    // because it's the only way to revive a package whose child is actually gone.
    if reason.skip_on_same_rate() {
        if let Some(prev) = handle.last_pkg_fee_rate {
            if target <= prev {
                info!(
                    %parent_txid,
                    ?target,
                    last = ?prev,
                    ?reason,
                    "target ≤ last bump rate; no-op (avoiding wasted RBF)"
                );
                return Ok(false);
            }
        }
    }

    // ── 4.5 Skip when another watchtower already covers a shared anchor ─────
    //
    // Only `MultiAnchorBearing` reaches this check. Every other anchor belongs to one
    // operator, so nobody else can spend it.
    //
    // A `MultiAnchor` output carries one leaf per watchtower, and every watchtower bumps the
    // same output. Their children conflict, so one wins each round and the rest are rejected.
    // Without this check the losers rebuild, re-sign, and resubmit on every trigger, for as
    // long as the parent stays unconfirmed. Each of those attempts costs a signing round trip
    // and leaves a warning in the log.
    //
    // The check is not a lock. Two watchtowers can read `Unspent` in the same instant and both
    // build. That race is bounded to one round, because the loser observes the winner on the
    // next trigger. The submission remains the authority, and `perform_bump` still handles a
    // rejection.
    if let CpfpStrategy::MultiAnchorBearing { anchor_vout, .. } = &strategy {
        let anchor = OutPoint {
            txid: parent_txid,
            vout: *anchor_vout,
        };
        // An error here is not fatal. The lookup is an optimisation, so fall through to the
        // build and let the submission decide.
        match ctx.mempool.anchor_spend_state(anchor).await {
            Ok(AnchorSpendState::SpentInMempool {
                spender,
                pkg_fee_rate: existing,
            }) if existing >= target => {
                // This skip ends the bump sequence, so the `replacing` hand-over of the
                // next build never runs. Drop the lease of the last child here instead,
                // but only when the winning child is not ours. When our own child holds
                // the anchor at the target, its funding must stay held. A release at that
                // point lets a concurrent build double-spend the funding and evict our own
                // child.
                if handle.last_child_txid != Some(spender) {
                    handle.last_child_lease = None;
                    handle.last_child_txid = None;
                    handle.last_child_fee = None;
                }
                debug!(
                    %parent_txid,
                    ?target,
                    ?existing,
                    %spender,
                    "anchor already bumped to the target; skipping"
                );
                return Ok(false);
            }
            Ok(AnchorSpendState::Confirmed) => {
                // The parent is confirmed. If a competitor's child won, this release
                // frees our dead child's funding. If our child won, its funding is spent
                // on-chain and the release has one bounded side effect: until the next
                // sync, `list_unspent` still lists those outpoints, so builds can select
                // a spent input and be rejected. A sync ends the window.
                handle.last_child_lease = None;
                handle.last_child_txid = None;
                handle.last_child_fee = None;
                debug!(
                    %parent_txid,
                    "anchor already spent by a confirmed transaction; skipping"
                );
                return Ok(false);
            }
            Ok(_) => {}
            Err(e) => {
                debug!(%parent_txid, error = %e, "anchor spend lookup failed; building anyway");
            }
        }
    }

    // ── 5. Build the child via the wallet ───────────────────────────────────
    let replacing: Option<&dyn FundingLease> = handle.last_child_lease.as_deref();
    // The RBF floor only applies while there is a live child to replace. A prior child
    // recorded but since evicted (lost anchor race, confirmed competitor) clears the handle
    // through the release paths, so `last_child_fee` here always describes the mempool
    // incumbent we are replacing.
    let prior_child_fee = handle
        .last_child_fee
        .filter(|_| handle.last_child_txid.is_some());
    let funded = ctx
        .wallet
        .build_cpfp_child(parent, strategy.clone(), target, replacing, prior_child_fee)
        .await
        .map_err(CpfpError::Wallet)?;

    // Take the new lease into the handle NOW, before any of the fallible steps below.
    //
    // The lease frees its outpoints when the last clone drops. Every step between here and
    // submission can fail: the anchor signer, the wallet signer, the sighash, the PSBT
    // extraction, and the package submission. The handle must own the lease across all of
    // them, so that the caller's write-back keeps it and the next bump passes it as
    // `replacing`. This assignment also drops the lease of the child that the new child
    // supersedes, once the caller writes the handle back.
    //
    // Record the fee together with the lease. The fee is the floor for the next
    // replacement (BIP-125 rule 4). If submission fails below, the prior child stays in
    // the mempool and pays less than the recorded fee. The floor is then conservative,
    // which is safe: the next child pays slightly more than the rule requires.
    handle.last_child_lease = Some(funded.lease);
    handle.last_child_fee = funded.psbt.fee().ok();

    // ── 6. Sign each input still lacking final_script_witness ─────────────
    //
    // The wallet's PSBT may be fully unsigned, partially signed, or fully signed (see
    // [`CpfpWallet`]'s "PSBT-signing contract" doc). We inspect each input's
    // `final_script_witness` and only sign the ones that are still unsigned:
    //
    // - For `AnchorBearing`: at most one anchor input (foreign, signed via `anchor_input_signer`) +
    //   N wallet funding inputs (signed via `wallet_input_signer`).
    // - For `ParentTxCombined`: all inputs are operator-controlled outputs (the payout output +
    //   wallet funding inputs); every still-unsigned one goes through `wallet_input_signer`. No
    //   anchor signer is invoked.
    //
    // Backends matter here: descriptor-only wallets (NativeGeneralWallet) return fully
    // unsigned PSBTs and every input gets signed below; create-and-sign backends
    // (Fireblocks-style) return wallet funding inputs already signed and only the foreign
    // anchor input unsigned — the skip checks preserve the wallet's signatures.
    let mut psbt = funded.psbt;
    let anchor_outpoint_opt = match &strategy {
        CpfpStrategy::AnchorBearing { anchor_vout, .. }
        | CpfpStrategy::MultiAnchorBearing { anchor_vout, .. } => Some(OutPoint {
            txid: parent_txid,
            vout: *anchor_vout,
        }),
        CpfpStrategy::ParentTxCombined { .. } => None,
    };

    let (anchor_input_idx, wallet_input_idxs): (Option<usize>, Vec<usize>) = {
        let mut anchor = None;
        let mut wallet = Vec::with_capacity(psbt.inputs.len());
        for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
            if Some(txin.previous_output) == anchor_outpoint_opt {
                anchor = Some(i);
            } else {
                wallet.push(i);
            }
        }
        (anchor, wallet)
    };

    if !matches!(strategy, CpfpStrategy::ParentTxCombined { .. }) {
        // The wallet promised to add the anchor as a foreign UTXO; sanity-check that the
        // PSBT actually contains it before signing.
        // `PsbtExtract`, not `Wallet`: this check runs after the build, and the handle
        // already owns the lease on the funding inputs. The caller's write-back keeps that
        // lease, or drops it and frees the inputs.
        let anchor_idx = anchor_input_idx.ok_or_else(|| {
            CpfpError::PsbtExtract(format!(
                "wallet-built child does not contain expected anchor outpoint for parent {parent_txid}"
            ))
        })?;
        // Same skip-if-already-signed semantics as the wallet-input loop below: a wallet
        // backend that happens to hold the musig2 (anchor) key in addition to the general
        // key may pre-sign the anchor input as part of its create-and-sign API. Respect
        // that rather than overwriting.
        if psbt.inputs[anchor_idx].final_script_witness.is_none() {
            let witness = match &strategy {
                // Key-path: sign the tweaked output key, witness is the bare signature.
                CpfpStrategy::AnchorBearing { .. } => {
                    let sighash =
                        compute_input_sighash(&psbt, anchor_idx).map_err(CpfpError::PsbtExtract)?;
                    let sig = (ctx.anchor_input_signer)(Message::from(sighash))
                        .await
                        .map_err(CpfpError::AnchorSigner)?;
                    let mut witness = Witness::new();
                    witness.push(sig.as_ref());
                    witness
                }
                // Script-path: the sighash commits to the leaf, the signature is untweaked,
                // and the witness carries the leaf script and control block after it.
                CpfpStrategy::MultiAnchorBearing {
                    leaf_script,
                    control_block,
                    ..
                } => {
                    let sighash = compute_script_path_sighash(&psbt, anchor_idx, leaf_script)
                        .map_err(CpfpError::PsbtExtract)?;
                    let sig = (ctx.multi_anchor_signer)(Message::from(sighash))
                        .await
                        .map_err(CpfpError::AnchorSigner)?;
                    let mut witness = Witness::new();
                    witness.push(sig.as_ref());
                    witness.push(leaf_script.to_bytes());
                    witness.push(control_block.serialize());
                    witness
                }
                CpfpStrategy::ParentTxCombined { .. } => {
                    unreachable!("guarded by the enclosing `if`")
                }
            };
            psbt.inputs[anchor_idx].final_script_witness = Some(witness);
        }
    }

    // Skip inputs that the wallet already signed. `NativeGeneralWallet` returns fully-unsigned
    // PSBTs (it's descriptor-only and has no key material), so every wallet input goes through
    // `wallet_input_signer` below. A Fireblocks-style backend typically does create-and-sign in
    // one API call, leaving the funding inputs already-signed and only the foreign anchor
    // input unsigned — for that case we MUST NOT re-sign and clobber the wallet's witness with
    // one computed against a key the wallet doesn't actually control. The skip makes the
    // [`CpfpWallet`] trait contract backend-agnostic: "return a PSBT where any input still
    // without a `final_script_witness` is signable via `wallet_input_signer`."
    for idx in wallet_input_idxs {
        if psbt.inputs[idx].final_script_witness.is_some() {
            continue;
        }
        let sighash = compute_input_sighash(&psbt, idx).map_err(CpfpError::PsbtExtract)?;
        let sig = (ctx.wallet_input_signer)(Message::from(sighash))
            .await
            .map_err(CpfpError::WalletSigner)?;
        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        psbt.inputs[idx].final_script_witness = Some(witness);
    }

    // ── 7. Finalize PSBT → child Transaction ───────────────────────────────
    //
    // Defensive sanity check: every input must have `final_script_witness` set, otherwise
    // `extract_tx` produces a witness-less tx that bitcoind would reject downstream.
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.final_script_witness.is_none() {
            return Err(CpfpError::PsbtExtract(format!(
                "PSBT input {i} has no final_script_witness after signing; refusing to extract"
            )));
        }
    }
    let child = psbt
        .extract_tx()
        .map_err(|e| CpfpError::PsbtExtract(format!("{e:?}")))?;
    let child_txid = child.compute_txid();

    // ── 8. submit_package([parent, child]) ──────────────────────────────────
    let summary = ctx.mempool.submit_package(&[parent.clone(), child]).await?;

    info!(
        %parent_txid,
        %child_txid,
        ?target,
        replaced = ?summary.replaced,
        "submitted CPFP package"
    );

    // ── 9. Update handle ────────────────────────────────────────────────────
    //
    // The lease was already recorded right after funding (see above) so a failure
    // anywhere in between still hands the leases back on the next bump. The remaining two
    // fields describe what is actually in the mempool, so they only advance on success.
    handle.last_pkg_fee_rate = Some(target);
    handle.last_child_txid = Some(child_txid);

    Ok(true)
}

/// Computes the BIP-341 **script-path** sighash for one input of a funded child PSBT.
///
/// Differs from [`compute_input_sighash`] in that the message commits to the specific leaf being
/// satisfied (via its [`TapLeafHash`]), so a signature made for one leaf cannot be replayed
/// against another. Used for [`CpfpStrategy::MultiAnchorBearing`] anchors, whose leaves are
/// `<watchtower_pubkey> OP_CHECKSIG`.
fn compute_script_path_sighash(
    psbt: &Psbt,
    input_idx: usize,
    leaf_script: &ScriptBuf,
) -> Result<bitcoin::TapSighash, String> {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| format!("PSBT input {i}: witness_utxo not populated"))
        })
        .collect::<Result<_, _>>()?;

    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    cache
        .taproot_script_spend_signature_hash(
            input_idx,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("script-path sighash compute (input {input_idx}): {e:?}"))
}

/// Computes the BIP-341 key-path Taproot sighash for one input of a funded child PSBT.
///
/// Uses [`TapSighashType::Default`] (sighash byte omitted from the witness; signature is the
/// bare 64-byte Schnorr signature). Requires every PSBT input to have `witness_utxo`
/// populated — BDK populates these on every wallet-selected input, and the anchor adapter
/// populates it for the foreign anchor input.
fn compute_input_sighash(psbt: &Psbt, input_idx: usize) -> Result<bitcoin::TapSighash, String> {
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| format!("PSBT input {i}: witness_utxo not populated"))
        })
        .collect::<Result<_, _>>()?;

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    cache
        .taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| format!("sighash compute (input {input_idx}): {e:?}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use bitcoin::{
        absolute,
        hashes::Hash,
        opcodes, script,
        secp256k1::{Keypair, SECP256K1},
        taproot::{LeafVersion, TaprootBuilder},
        transaction::Version,
        Address, Network, TxIn, XOnlyPublicKey,
    };

    use super::*;
    use crate::submitpackage::SubmitPackageSummary;

    // ── Test doubles ─────────────────────────────────────────────────────────

    #[derive(Debug)]
    pub(crate) struct FakeFeeSource {
        rate: Mutex<Result<FeeRate, String>>,
    }
    impl FakeFeeSource {
        pub(crate) fn returning(rate: FeeRate) -> Self {
            Self {
                rate: Mutex::new(Ok(rate)),
            }
        }
        fn failing() -> Self {
            Self {
                rate: Mutex::new(Err("fake fee source failure".to_string())),
            }
        }
    }
    impl CpfpFeeSource for FakeFeeSource {
        fn estimate(&self) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send {
            let r = self.rate.lock().unwrap().clone();
            async move { r }
        }
    }

    /// A lease that appends its outpoints to a shared log when it drops.
    ///
    /// The tests read that log to make sure that each path which stops the bumps returns the
    /// funding inputs of the last child. A production lease returns them to the wallet. This
    /// one records the same event.
    #[derive(Debug)]
    pub(crate) struct FakeLease {
        outpoints: Vec<OutPoint>,
        released: Arc<Mutex<Vec<OutPoint>>>,
    }
    impl FundingLease for FakeLease {
        fn outpoints(&self) -> &[OutPoint] {
            &self.outpoints
        }
    }
    impl Drop for FakeLease {
        fn drop(&mut self) {
            self.released
                .lock()
                .unwrap()
                .extend_from_slice(&self.outpoints);
        }
    }

    #[derive(Debug)]
    pub(crate) struct FakeWallet {
        psbt_template: Mutex<Option<Psbt>>,
        spent_template: Vec<OutPoint>,
        error: Option<String>,
        /// Outpoints of every lease that has dropped, in drop order.
        pub(crate) released: Arc<Mutex<Vec<OutPoint>>>,
    }
    impl FakeWallet {
        pub(crate) fn returning(psbt: Psbt, spent: Vec<OutPoint>) -> Self {
            Self {
                psbt_template: Mutex::new(Some(psbt)),
                spent_template: spent,
                error: None,
                released: Arc::new(Mutex::new(Vec::new())),
            }
        }
        pub(crate) fn failing(msg: &str) -> Self {
            Self {
                psbt_template: Mutex::new(None),
                spent_template: Vec::new(),
                error: Some(msg.to_string()),
                released: Arc::new(Mutex::new(Vec::new())),
            }
        }
        /// Builds a lease over `outpoints` that reports its own drop to this wallet.
        pub(crate) fn lease(&self, outpoints: Vec<OutPoint>) -> Arc<dyn FundingLease> {
            Arc::new(FakeLease {
                outpoints,
                released: Arc::clone(&self.released),
            })
        }
    }
    impl CpfpWallet for FakeWallet {
        fn build_cpfp_child(
            &self,
            _parent: &Transaction,
            _strategy: CpfpStrategy,
            _target_pkg_fee_rate: FeeRate,
            _replacing: Option<&dyn FundingLease>,
            _prior_child_fee: Option<Amount>,
        ) -> impl std::future::Future<Output = Result<WalletFundedPsbt, String>> + Send {
            let err = self.error.clone();
            let psbt = self.psbt_template.lock().unwrap().clone();
            let lease = self.lease(self.spent_template.clone());
            async move {
                if let Some(e) = err {
                    return Err(e);
                }
                Ok(WalletFundedPsbt {
                    psbt: psbt.expect("test must seed a psbt template"),
                    lease,
                })
            }
        }
    }

    #[derive(Debug)]
    pub(crate) struct FakeSubmitter {
        pub(crate) result: Mutex<Result<SubmitPackageSummary, String>>,
        pub(crate) captured: Mutex<Vec<Vec<Transaction>>>,
        pub(crate) spend_state: Mutex<AnchorSpendState>,
    }
    impl FakeSubmitter {
        pub(crate) fn ok() -> Self {
            Self {
                result: Mutex::new(Ok(SubmitPackageSummary {
                    tx_results: Default::default(),
                    replaced: Vec::new(),
                })),
                captured: Mutex::new(Vec::new()),
                spend_state: Mutex::new(AnchorSpendState::Unspent),
            }
        }
        pub(crate) fn failing(reason: &str) -> Self {
            Self {
                result: Mutex::new(Err(reason.to_string())),
                captured: Mutex::new(Vec::new()),
                spend_state: Mutex::new(AnchorSpendState::Unspent),
            }
        }
        pub(crate) fn with_spend_state(self, state: AnchorSpendState) -> Self {
            *self.spend_state.lock().unwrap() = state;
            self
        }
    }
    impl CpfpMempool for FakeSubmitter {
        fn submit_package(
            &self,
            txs: &[Transaction],
        ) -> impl std::future::Future<Output = Result<SubmitPackageSummary, SubmitPackageError>> + Send
        {
            self.captured.lock().unwrap().push(txs.to_vec());
            let snapshot: Result<SubmitPackageSummary, String> = match &*self.result.lock().unwrap()
            {
                Ok(s) => Ok(s.clone()),
                Err(e) => Err(e.clone()),
            };
            async move {
                match snapshot {
                    Ok(s) => Ok(s),
                    Err(msg) => Err(SubmitPackageError::Rejected {
                        message: msg,
                        tx_errors: Vec::new(),
                    }),
                }
            }
        }

        /// Reports the configured spend state (default: unspent, so tests exercise the
        /// build path). The full contention flow is covered end to end against a live
        /// bitcoind; the unit tests use [`FakeSubmitter::with_spend_state`] to pin the
        /// lease bookkeeping on the skip paths.
        async fn anchor_spend_state(&self, _anchor: OutPoint) -> Result<AnchorSpendState, String> {
            Ok(*self.spend_state.lock().unwrap())
        }
    }

    pub(crate) fn fake_input_signer_ok() -> InputSigner {
        Arc::new(|_msg: Message| {
            Box::pin(async move {
                // Schnorr signature is 64 bytes; bytes don't have to verify for unit tests of
                // the bump-loop control flow.
                let sig = Signature::from_slice(&[7u8; 64]).expect("64 bytes is a valid sig");
                Ok::<_, String>(sig)
            })
        })
    }

    pub(crate) fn fake_input_signer_failing(message: &'static str) -> InputSigner {
        Arc::new(move |_msg: Message| {
            let m = message.to_string();
            Box::pin(async move { Err(m) })
        })
    }

    // ── Test fixtures ────────────────────────────────────────────────────────

    pub(crate) fn test_keypair_and_xonly() -> (Keypair, XOnlyPublicKey) {
        let kp = Keypair::from_seckey_slice(SECP256K1, &[5u8; 32]).unwrap();
        let (x, _parity) = kp.x_only_public_key();
        (kp, x)
    }

    /// Build a synthetic parent with a keyed-Taproot anchor at vout 0.
    pub(crate) fn synthetic_parent(
        anchor_internal_key: XOnlyPublicKey,
        anchor_value: Amount,
    ) -> Transaction {
        let addr = Address::p2tr(SECP256K1, anchor_internal_key, None, Network::Regtest);
        Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: anchor_value,
                script_pubkey: addr.script_pubkey(),
            }],
        }
    }

    /// Build a synthetic child PSBT with the right shape: anchor input + funding input + change.
    /// Inputs carry only `witness_utxo` (+ `tap_internal_key` on the anchor); `perform_bump`
    /// is responsible for signing both inputs via its caller-provided signers.
    pub(crate) fn synthetic_child_psbt(
        parent: &Transaction,
        anchor_vout: u32,
        anchor_internal_key: XOnlyPublicKey,
    ) -> Psbt {
        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: anchor_vout,
        };
        let funding_outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
            vout: 0,
        };
        let wallet_script = Address::p2tr(
            SECP256K1,
            test_keypair_and_xonly().1,
            None,
            Network::Regtest,
        )
        .script_pubkey();
        let child_tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: anchor_outpoint,
                    ..Default::default()
                },
                TxIn {
                    previous_output: funding_outpoint,
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(49_500),
                script_pubkey: wallet_script.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(child_tx).expect("unsigned tx must convert");
        psbt.inputs[0].witness_utxo = Some(parent.output[anchor_vout as usize].clone());
        psbt.inputs[0].tap_internal_key = Some(anchor_internal_key);
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: wallet_script,
        });
        psbt
    }

    /// Build a synthetic child PSBT for the `ParentTxCombined` shape: payout input + funding
    /// input + change. Both inputs carry only `witness_utxo`; `perform_bump` signs them via
    /// `wallet_input_signer`.
    fn synthetic_parent_combined_child_psbt(
        payout_outpoint: OutPoint,
        wallet_script: bitcoin::ScriptBuf,
    ) -> Psbt {
        let funding_outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[2u8; 32]).unwrap(),
            vout: 0,
        };
        let child_tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: payout_outpoint,
                    ..Default::default()
                },
                TxIn {
                    previous_output: funding_outpoint,
                    ..Default::default()
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: wallet_script.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(child_tx).expect("unsigned tx must convert");
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: wallet_script.clone(),
        });
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: wallet_script,
        });
        psbt
    }

    fn context<F, W, P>(
        fee_source: Arc<F>,
        wallet: Arc<W>,
        submitter: Arc<P>,
        anchor_signer: InputSigner,
        wallet_signer: InputSigner,
        max_fee_rate: FeeRate,
    ) -> CpfpContext<W, F, P>
    where
        F: CpfpFeeSource + 'static,
        W: CpfpWallet + 'static,
        P: CpfpMempool + 'static,
    {
        CpfpContext {
            wallet,
            fee_source,
            multi_anchor_signer: anchor_signer.clone(),
            anchor_input_signer: anchor_signer,
            wallet_input_signer: wallet_signer,
            max_fee_rate,
            mempool: submitter,
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    pub(crate) const PROTOCOL_FLOOR: FeeRate = FeeRate::from_sat_per_vb_unchecked(2);

    pub(crate) fn anchor_strategy(anchor_key: XOnlyPublicKey) -> CpfpStrategy {
        CpfpStrategy::AnchorBearing {
            anchor_vout: 0,
            anchor_internal_key: anchor_key,
            parent_fee: Amount::from_sat(220),
        }
    }

    /// A minimal one-leaf `MultiAnchorBearing` strategy. The step-4.5 contention skip is
    /// gated on this variant, so the lease-release tests need a structurally valid leaf +
    /// control block even though the skip never spends the anchor.
    fn multi_anchor_strategy(anchor_key: XOnlyPublicKey) -> CpfpStrategy {
        let leaf = script::Builder::new()
            .push_slice(anchor_key.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("depth 0 leaf is always valid")
            .finalize(SECP256K1, anchor_key)
            .expect("single-leaf tree finalizes");
        let control_block = spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .expect("control block for the only leaf");
        CpfpStrategy::MultiAnchorBearing {
            anchor_vout: 0,
            leaf_script: leaf,
            control_block,
            parent_fee: Amount::from_sat(220),
        }
    }

    fn seeded_handle(wallet: &FakeWallet, inputs: &[OutPoint], our_child: Txid) -> CpfpHandle {
        CpfpHandle {
            last_child_lease: Some(wallet.lease(inputs.to_vec())),
            last_pkg_fee_rate: Some(FeeRate::from_sat_per_vb_unchecked(3)),
            last_child_txid: Some(our_child),
            last_child_fee: Some(Amount::from_sat(500)),
        }
    }

    /// The outpoints that the handle's lease holds, or an empty vector when it holds none.
    fn held_by(handle: &CpfpHandle) -> Vec<OutPoint> {
        handle
            .last_child_lease
            .as_deref()
            .map(|lease| lease.outpoints().to_vec())
            .unwrap_or_default()
    }

    fn contention_context(
        wallet: Arc<FakeWallet>,
        submitter: Arc<FakeSubmitter>,
    ) -> CpfpContext<FakeWallet, FakeFeeSource, FakeSubmitter> {
        context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(8).unwrap(),
            )),
            wallet,
            submitter,
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        )
    }

    /// A competitor's child covers the shared anchor at (or above) our target: we stand
    /// down, and standing down must hand the last child's funding leases back — the next
    /// build for this parent may never come, and nothing else records those outpoints.
    #[tokio::test]
    async fn losing_a_shared_anchor_releases_the_last_childs_funding() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ours = Txid::from_byte_array([0xAA; 32]);
        let theirs = Txid::from_byte_array([0xBB; 32]);
        let inputs = [
            OutPoint::new(Txid::from_byte_array([1; 32]), 0),
            OutPoint::new(Txid::from_byte_array([2; 32]), 1),
        ];
        let wallet = Arc::new(FakeWallet::failing("skip must not build"));
        let submitter = Arc::new(
            FakeSubmitter::failing("skip must not submit").with_spend_state(
                AnchorSpendState::SpentInMempool {
                    spender: theirs,
                    pkg_fee_rate: FeeRate::from_sat_per_vb_unchecked(10),
                },
            ),
        );
        let ctx = contention_context(wallet.clone(), submitter);
        let mut handle = seeded_handle(&wallet, &inputs, ours);
        let bumped = perform_bump(
            &ctx,
            &parent,
            multi_anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
        )
        .await
        .expect("losing the anchor is a skip, not an error");
        assert!(!bumped);
        assert_eq!(*wallet.released.lock().unwrap(), inputs.to_vec());
        assert!(handle.last_child_lease.is_none());
    }

    /// Our own child holds the anchor at the target. This is the normal state. The leases
    /// must stay: a release lets a concurrent build double-spend the live child's funding
    /// and evict our own child.
    #[tokio::test]
    async fn our_own_winning_child_keeps_its_funding_leases() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ours = Txid::from_byte_array([0xAA; 32]);
        let inputs = [OutPoint::new(Txid::from_byte_array([1; 32]), 0)];
        let wallet = Arc::new(FakeWallet::failing("skip must not build"));
        let submitter = Arc::new(
            FakeSubmitter::failing("skip must not submit").with_spend_state(
                AnchorSpendState::SpentInMempool {
                    spender: ours,
                    pkg_fee_rate: FeeRate::from_sat_per_vb_unchecked(10),
                },
            ),
        );
        let ctx = contention_context(wallet.clone(), submitter);
        let mut handle = seeded_handle(&wallet, &inputs, ours);
        let bumped = perform_bump(
            &ctx,
            &parent,
            multi_anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
        )
        .await
        .expect("holding the anchor is a skip, not an error");
        assert!(!bumped);
        assert!(wallet.released.lock().unwrap().is_empty());
        assert_eq!(held_by(&handle), inputs.to_vec());
    }

    /// The anchor is spent by a confirmed transaction: bumping is over for this parent,
    /// whoever won. Standing down releases the leases; if our own child won, its funding is
    /// spent on-chain and the release is a harmless no-op ahead of the sync prune.
    #[tokio::test]
    async fn a_confirmed_anchor_spend_releases_the_last_childs_funding() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ours = Txid::from_byte_array([0xAA; 32]);
        let inputs = [OutPoint::new(Txid::from_byte_array([1; 32]), 0)];
        let wallet = Arc::new(FakeWallet::failing("skip must not build"));
        let submitter = Arc::new(
            FakeSubmitter::failing("skip must not submit")
                .with_spend_state(AnchorSpendState::Confirmed),
        );
        let ctx = contention_context(wallet.clone(), submitter);
        let mut handle = seeded_handle(&wallet, &inputs, ours);
        let bumped = perform_bump(
            &ctx,
            &parent,
            multi_anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
        )
        .await
        .expect("a confirmed spend is a skip, not an error");
        assert!(!bumped);
        assert_eq!(*wallet.released.lock().unwrap(), inputs.to_vec());
        assert!(handle.last_child_lease.is_none());
    }

    #[tokio::test]
    async fn bump_skipped_when_target_at_or_below_floor() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(2).unwrap(),
            )),
            Arc::new(FakeWallet::failing(
                "wallet must not be called when skipping",
            )),
            Arc::new(FakeSubmitter::failing("submitter must not be called")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let bumped = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .expect("at-floor must succeed-skip");
        assert!(!bumped);
        assert!(handle.last_pkg_fee_rate.is_none());
    }

    #[tokio::test]
    async fn bump_skipped_when_parent_fee_alone_meets_target() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        // Target is above the floor, and the reason is reactive so the step-4 same-rate
        // skip can't fire — the only thing standing between perform_bump and the failing
        // wallet is the parent-fee baseline skip.
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(5).unwrap(),
            )),
            Arc::new(FakeWallet::failing(
                "wallet must not be called when the parent alone clears the target",
            )),
            Arc::new(FakeSubmitter::failing("submitter must not be called")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let overpaying = CpfpStrategy::AnchorBearing {
            anchor_vout: 0,
            anchor_internal_key: anchor_key,
            // Far more than 5 sat/vB over any plausible parent vsize.
            parent_fee: Amount::from_sat(50_000),
        };
        let mut handle = CpfpHandle::default();
        let bumped = perform_bump(
            &ctx,
            &parent,
            overpaying,
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::Tick,
        )
        .await
        .expect("overpaying parent must succeed-skip");
        assert!(!bumped);
        assert!(handle.last_pkg_fee_rate.is_none());
    }

    #[tokio::test]
    async fn eager_bump_skipped_when_target_not_above_last_rate() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(5).unwrap(),
            )),
            Arc::new(FakeWallet::failing("wallet must not be called")),
            Arc::new(FakeSubmitter::failing("submitter must not be called")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle {
            last_pkg_fee_rate: Some(FeeRate::from_sat_per_vb(5).unwrap()),
            ..Default::default()
        };
        let bumped = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .unwrap();
        assert!(!bumped);
    }

    #[tokio::test]
    async fn reactive_bump_rebuilds_even_at_same_rate() {
        // Regression for B3 (reviewer finding): when only the child is evicted, no
        // parent-side eviction event fires; the timer/block tick must rebuild even at the
        // same package fee rate to keep the child resident in the mempool.
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0, anchor_key);
        let submitter = Arc::new(FakeSubmitter::ok());
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(5).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            submitter.clone(),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(50).unwrap(),
        );
        let mut handle = CpfpHandle {
            last_pkg_fee_rate: Some(FeeRate::from_sat_per_vb(5).unwrap()),
            ..Default::default()
        };
        for reason in [
            BumpReason::NewBlock,
            BumpReason::Tick,
            BumpReason::ParentEvicted,
        ] {
            let bumped = perform_bump(
                &ctx,
                &parent,
                anchor_strategy(anchor_key),
                &mut handle,
                PROTOCOL_FLOOR,
                reason,
            )
            .await
            .unwrap_or_else(|e| panic!("reactive bump ({reason:?}) must succeed: {e}"));
            assert!(
                bumped,
                "reactive bump ({reason:?}) must rebuild at same rate"
            );
        }
        assert_eq!(submitter.captured.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn happy_path_submits_package_and_updates_handle() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0, anchor_key);
        let wallet_funding = vec![OutPoint {
            txid: bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
            vout: 0,
        }];

        let submitter = Arc::new(FakeSubmitter::ok());
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, wallet_funding.clone())),
            submitter.clone(),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(50).unwrap(),
        );

        let mut handle = CpfpHandle::default();
        let bumped = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .expect("happy path must submit");
        assert!(bumped);

        // handle is updated
        assert_eq!(
            handle.last_pkg_fee_rate,
            Some(FeeRate::from_sat_per_vb(10).unwrap())
        );
        assert_eq!(held_by(&handle), wallet_funding);
        assert!(handle.last_child_txid.is_some());

        // submitter received [parent, child]
        let captured = submitter.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].len(), 2);
        assert_eq!(captured[0][0].compute_txid(), parent.compute_txid());
    }

    #[tokio::test]
    async fn target_above_cap_is_clamped() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0, anchor_key);

        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(100).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            Arc::new(FakeSubmitter::ok()),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let bumped = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .unwrap();
        assert!(bumped);
        assert_eq!(
            handle.last_pkg_fee_rate,
            Some(FeeRate::from_sat_per_vb(20).unwrap())
        );
    }

    #[tokio::test]
    async fn fee_source_failure_surfaces() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ctx = context(
            Arc::new(FakeFeeSource::failing()),
            Arc::new(FakeWallet::failing("wallet must not be called")),
            Arc::new(FakeSubmitter::failing("submitter must not be called")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let err = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CpfpError::FeeSource(_)));
        assert!(handle.last_pkg_fee_rate.is_none());
    }

    #[tokio::test]
    async fn anchor_signer_failure_surfaces() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0, anchor_key);

        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            Arc::new(FakeSubmitter::failing(
                "must not be called when signer fails",
            )),
            fake_input_signer_failing("anchor sign boom"),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let err = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CpfpError::AnchorSigner(_)));
        assert!(handle.last_pkg_fee_rate.is_none());
    }

    #[tokio::test]
    async fn wallet_input_signer_failure_surfaces() {
        // Regression for B2: every non-anchor input must be signed via wallet_input_signer.
        // Failure there must propagate (not silently produce a witness-less tx).
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0, anchor_key);

        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            Arc::new(FakeSubmitter::failing(
                "must not be called when signer fails",
            )),
            fake_input_signer_ok(),
            fake_input_signer_failing("wallet sign boom"),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let err = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, CpfpError::WalletSigner(_)),
            "expected WalletSigner; got {err:?}"
        );
        assert!(handle.last_pkg_fee_rate.is_none());
    }

    #[tokio::test]
    async fn presigned_wallet_inputs_are_not_re_signed() {
        // Backend-agnostic CpfpWallet contract: if `build_cpfp_child` returns a PSBT
        // whose wallet inputs are ALREADY signed (the create-and-sign pattern that
        // Fireblocks-like backends follow), perform_bump MUST NOT overwrite the witness.
        // Use a wallet_input_signer that panics if called — the test passes only if
        // perform_bump skips signing for the pre-signed input.
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let mut psbt = synthetic_child_psbt(&parent, 0, anchor_key);
        // Pre-populate the funding input's witness with a sentinel — this is what a
        // create-and-sign backend would have done. perform_bump must respect it.
        let sentinel = Signature::from_slice(&[0x42u8; 64]).expect("64 bytes");
        let mut sentinel_witness = Witness::new();
        sentinel_witness.push(sentinel.as_ref());
        psbt.inputs[1].final_script_witness = Some(sentinel_witness.clone());

        let panicking_wallet_signer: InputSigner = Arc::new(|_msg: Message| {
            Box::pin(async move {
                panic!("wallet_input_signer must NOT be called for already-signed inputs")
            })
        });

        let submitter = Arc::new(FakeSubmitter::ok());
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            submitter.clone(),
            fake_input_signer_ok(),
            panicking_wallet_signer,
            FeeRate::from_sat_per_vb(50).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let bumped = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .expect("presigned-wallet-input path must submit without invoking wallet signer");
        assert!(bumped);

        // The submitted child's funding-input witness must still be the sentinel — proves
        // perform_bump didn't overwrite it.
        let captured = submitter.captured.lock().unwrap();
        let child = &captured[0][1];
        assert_eq!(
            child.input[1].witness, sentinel_witness,
            "presigned wallet-input witness must survive perform_bump unchanged"
        );
    }

    #[tokio::test]
    async fn presigned_anchor_input_is_not_re_signed() {
        // Same contract for the anchor input — supports backends that hold the musig2 key
        // alongside the general key (e.g. an operator who puts ALL keys in Fireblocks).
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let mut psbt = synthetic_child_psbt(&parent, 0, anchor_key);
        let sentinel = Signature::from_slice(&[0x37u8; 64]).expect("64 bytes");
        let mut sentinel_witness = Witness::new();
        sentinel_witness.push(sentinel.as_ref());
        psbt.inputs[0].final_script_witness = Some(sentinel_witness.clone());

        let panicking_anchor_signer: InputSigner = Arc::new(|_msg: Message| {
            Box::pin(async move {
                panic!("anchor_input_signer must NOT be called for an already-signed anchor")
            })
        });

        let submitter = Arc::new(FakeSubmitter::ok());
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            submitter.clone(),
            panicking_anchor_signer,
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(50).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let bumped = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .expect("presigned-anchor path must submit without invoking anchor signer");
        assert!(bumped);

        let captured = submitter.captured.lock().unwrap();
        let child = &captured[0][1];
        assert_eq!(
            child.input[0].witness, sentinel_witness,
            "presigned anchor witness must survive perform_bump unchanged"
        );
    }

    #[tokio::test]
    async fn parent_tx_combined_happy_path_no_anchor_signer_call() {
        // ParentTxCombined parents have no foreign-key input. The bump loop must:
        // (a) build the child via the wallet (which signs everything itself),
        // (b) NOT invoke the anchor signer,
        // (c) submit the package as usual.
        //
        // We assert (b) by supplying an anchor signer that panics if called — the test would
        // panic instead of pass if the bump loop incorrectly entered the AnchorBearing path.
        let wallet_script = Address::p2tr(
            SECP256K1,
            test_keypair_and_xonly().1,
            None,
            Network::Regtest,
        )
        .script_pubkey();
        let payout_outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[42u8; 32]).unwrap(),
            vout: 1,
        };
        // The "parent" is a dummy v3 tx — its content doesn't matter for ParentTxCombined,
        // since the wallet builds the child against the payout outpoint directly.
        let parent = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: wallet_script.clone(),
            }],
        };
        let psbt = synthetic_parent_combined_child_psbt(payout_outpoint, wallet_script);

        let panicking_anchor_signer: InputSigner = Arc::new(|_msg: Message| {
            Box::pin(async move {
                panic!("anchor signer must NOT be called for ParentTxCombined strategies");
            })
        });

        let submitter = Arc::new(FakeSubmitter::ok());
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, vec![payout_outpoint])),
            submitter.clone(),
            panicking_anchor_signer,
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(50).unwrap(),
        );

        let mut handle = CpfpHandle::default();
        let strategy = CpfpStrategy::ParentTxCombined {
            payout_outpoint,
            parent_fee: Amount::from_sat(300),
        };
        let bumped = perform_bump(
            &ctx,
            &parent,
            strategy,
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .expect("ParentTxCombined happy path must submit");
        assert!(bumped);

        assert_eq!(
            handle.last_pkg_fee_rate,
            Some(FeeRate::from_sat_per_vb(10).unwrap())
        );
        assert!(handle.last_child_txid.is_some());

        // submitter received [parent, child]
        let captured = submitter.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].len(), 2);
        assert_eq!(captured[0][0].compute_txid(), parent.compute_txid());
    }

    #[tokio::test]
    async fn cached_fee_source_returns_initial_value() {
        let underlying = Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(7).unwrap(),
        ));
        let cache = CachedFeeSource::spawn(underlying, Duration::from_secs(60))
            .await
            .expect("initial refresh must succeed");
        assert_eq!(cache.current(), FeeRate::from_sat_per_vb(7).unwrap());
        // Trait impl returns the same.
        let via_trait = cache.estimate().await.unwrap();
        assert_eq!(via_trait, FeeRate::from_sat_per_vb(7).unwrap());
    }

    #[tokio::test]
    async fn cached_fee_source_propagates_initial_refresh_error() {
        let underlying = Arc::new(FakeFeeSource::failing());
        let result = CachedFeeSource::spawn(underlying, Duration::from_secs(60)).await;
        assert!(result.is_err(), "initial refresh failure must propagate");
    }

    /// Fee source whose result can be swapped mid-test, for exercising the background
    /// refresh loop of [`CachedFeeSource`].
    #[derive(Debug)]
    struct FlippableFeeSource {
        inner: Mutex<Result<FeeRate, String>>,
    }
    impl CpfpFeeSource for FlippableFeeSource {
        fn estimate(&self) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send {
            let r = self.inner.lock().unwrap().clone();
            async move { r }
        }
    }

    #[tokio::test]
    async fn cached_fee_source_retains_stale_value_when_refresh_fails() {
        // Initial refresh succeeds at 10 sat/vB; flip the underlying to fail; wait past a
        // few 5 ms refresh intervals (real time — the refresh loop runs on a spawned task);
        // the cache must still report the original 10 sat/vB.
        let flippable = Arc::new(FlippableFeeSource {
            inner: Mutex::new(Ok(FeeRate::from_sat_per_vb(10).unwrap())),
        });
        let cache = CachedFeeSource::spawn(flippable.clone(), Duration::from_millis(5))
            .await
            .unwrap();
        assert_eq!(cache.current(), FeeRate::from_sat_per_vb(10).unwrap());

        // Flip underlying to failing.
        *flippable.inner.lock().unwrap() = Err("transient blip".to_string());
        // Wait long enough for a refresh attempt to complete.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cache still reports 10.
        assert_eq!(cache.current(), FeeRate::from_sat_per_vb(10).unwrap());
    }

    #[tokio::test]
    async fn cached_fee_source_picks_up_refreshed_value() {
        // Same shape as the previous test, but the underlying flips to a new value.
        let flippable = Arc::new(FlippableFeeSource {
            inner: Mutex::new(Ok(FeeRate::from_sat_per_vb(5).unwrap())),
        });
        let cache = CachedFeeSource::spawn(flippable.clone(), Duration::from_millis(5))
            .await
            .unwrap();
        assert_eq!(cache.current(), FeeRate::from_sat_per_vb(5).unwrap());

        *flippable.inner.lock().unwrap() = Ok(FeeRate::from_sat_per_vb(30).unwrap());
        // Allow a few refresh ticks to fire.
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert_eq!(cache.current(), FeeRate::from_sat_per_vb(30).unwrap());
    }

    #[tokio::test]
    async fn submitpackage_failure_surfaces() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0, anchor_key);

        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            Arc::new(FakeSubmitter::failing("package-not-valid")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let err = perform_bump(
            &ctx,
            &parent,
            anchor_strategy(anchor_key),
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CpfpError::SubmitPackage(_)));
        assert!(handle.last_pkg_fee_rate.is_none());
    }

    /// Regression: a bump that dies *after* the wallet funded the child must still leave the
    /// funding inputs recorded on the handle.
    ///
    /// `build_cpfp_child` leases `funded.spent` on the way out, and the only thing that can ever
    /// hand those back is a subsequent bump passing them as `replacing`. Recording them only on
    /// the success path meant any rejection stranded the UTXOs for the process lifetime, and
    /// repeated failures walked the general wallet down to nothing.
    ///
    /// Exercised at both ends of the fallible stretch: package rejection (last step) and a
    /// wallet-signer failure (first step).
    #[tokio::test]
    async fn failure_after_funding_still_records_leases_for_release() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let wallet_funding = vec![OutPoint {
            txid: parent.compute_txid(),
            vout: 7,
        }];

        for (label, submitter, wallet_signer) in [
            (
                "package rejected",
                Arc::new(FakeSubmitter::failing("package-not-valid")),
                fake_input_signer_ok(),
            ),
            (
                "wallet signer failed",
                Arc::new(FakeSubmitter::ok()),
                fake_input_signer_failing("signer offline"),
            ),
        ] {
            let psbt = synthetic_child_psbt(&parent, 0, anchor_key);
            let ctx = context(
                Arc::new(FakeFeeSource::returning(
                    FeeRate::from_sat_per_vb(10).unwrap(),
                )),
                Arc::new(FakeWallet::returning(psbt, wallet_funding.clone())),
                submitter,
                fake_input_signer_ok(),
                wallet_signer,
                FeeRate::from_sat_per_vb(20).unwrap(),
            );
            let mut handle = CpfpHandle::default();
            let result = perform_bump(
                &ctx,
                &parent,
                anchor_strategy(anchor_key),
                &mut handle,
                PROTOCOL_FLOOR,
                BumpReason::NewJob,
            )
            .await;

            assert!(result.is_err(), "{label}: expected the bump to fail");
            // Nothing reached the mempool, so these must not advance.
            assert!(
                handle.last_pkg_fee_rate.is_none(),
                "{label}: fee rate must not advance on failure"
            );
            assert!(
                handle.last_child_txid.is_none(),
                "{label}: child txid must not advance on failure"
            );
            // But the leased inputs must be recorded, so the next bump releases them.
            assert_eq!(
                held_by(&handle),
                wallet_funding,
                "{label}: leased funding inputs must be recorded for release"
            );
        }
    }

    /// A constant-byte signer whose output is recognisable in the final witness, so a test can
    /// prove *which* signer produced a given signature rather than only that signing happened.
    fn fake_input_signer_const(byte: u8) -> InputSigner {
        Arc::new(move |_msg: Message| {
            Box::pin(async move {
                Ok::<_, String>(
                    Signature::from_slice(&[byte; 64]).expect("64 bytes is a valid sig"),
                )
            })
        })
    }

    /// The script-path (`MultiAnchorBearing`) bump must (a) route the anchor input through the
    /// dedicated `multi_anchor_signer` — NOT the tap-tweaked key-path signer — and (b) emit the
    /// BIP-341 script-path witness stack `[signature, leaf_script, control_block]` in exactly
    /// that order. A wrong signer or a reordered stack produces a transaction that fails script
    /// validation at broadcast, on the time-critical contest path, with no local signal.
    ///
    /// Sentinels make routing observable: the key-path signer errors if invoked at all, and the
    /// multi-anchor signer returns a recognisable constant signature that is then asserted
    /// byte-for-byte in the captured child.
    #[tokio::test]
    async fn multi_anchor_bump_routes_untweaked_signer_and_orders_witness() {
        use bitcoin::taproot::TaprootBuilder;

        // Two watchtower-style leaves; ours is leaf 0. Assembled directly with TaprootBuilder
        // because btc-tracker deliberately doesn't depend on the connector crate.
        let (_, our_key) = test_keypair_and_xonly();
        let derived_key = |seed: u8| {
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).expect("valid scalar");
            bitcoin::secp256k1::Keypair::from_secret_key(SECP256K1, &sk)
                .x_only_public_key()
                .0
        };
        let other_key = derived_key(0x11);
        let leaf = |key: XOnlyPublicKey| {
            bitcoin::script::Builder::new()
                .push_slice(key.serialize())
                .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
                .into_script()
        };
        let our_leaf = leaf(our_key);
        let spend_info = TaprootBuilder::new()
            .add_leaf(1, our_leaf.clone())
            .expect("depth 1 is valid")
            .add_leaf(1, leaf(other_key))
            .expect("depth 1 is valid")
            .finalize(SECP256K1, derived_key(0x22))
            .expect("tree finalizes");
        let control_block = spend_info
            .control_block(&(our_leaf.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .expect("leaf is in the tree");
        let anchor_spk = bitcoin::ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

        let parent = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(330),
                script_pubkey: anchor_spk,
            }],
        };
        // The synthetic child spends parent:0 (the anchor) + one wallet funding input; the
        // internal key it stamps on input 0 is irrelevant to the script-path branch.
        let psbt = synthetic_child_psbt(&parent, 0, our_key);
        let wallet_funding = vec![OutPoint {
            txid: parent.compute_txid(),
            vout: 9,
        }];

        let submitter = Arc::new(FakeSubmitter::ok());
        let ctx = CpfpContext {
            wallet: Arc::new(FakeWallet::returning(psbt, wallet_funding.clone())),
            fee_source: Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            // Key-path signer must never fire for a script-path anchor: if it does, the bump
            // errors and the assertions below fail loudly.
            anchor_input_signer: fake_input_signer_failing(
                "key-path anchor signer must not be called for MultiAnchorBearing",
            ),
            multi_anchor_signer: fake_input_signer_const(0xAA),
            wallet_input_signer: fake_input_signer_const(0xBB),
            max_fee_rate: FeeRate::from_sat_per_vb(20).unwrap(),
            mempool: submitter.clone(),
        };
        let strategy = CpfpStrategy::MultiAnchorBearing {
            anchor_vout: 0,
            leaf_script: our_leaf.clone(),
            control_block: control_block.clone(),
            parent_fee: Amount::from_sat(200),
        };
        let mut handle = CpfpHandle::default();
        let submitted = perform_bump(
            &ctx,
            &parent,
            strategy,
            &mut handle,
            PROTOCOL_FLOOR,
            BumpReason::NewJob,
        )
        .await
        .expect("script-path bump must succeed");
        assert!(submitted);
        assert_eq!(held_by(&handle), wallet_funding);

        let packages = submitter.captured.lock().unwrap();
        let child = &packages[0][1];

        // Anchor input: exactly the BIP-341 script-path stack, in order, signed by the
        // multi-anchor sentinel.
        let anchor_witness: Vec<&[u8]> = child.input[0].witness.iter().collect();
        assert_eq!(
            anchor_witness.len(),
            3,
            "script-path witness must be [sig, leaf_script, control_block]"
        );
        assert_eq!(
            anchor_witness[0], &[0xAA; 64],
            "anchor signature must come from multi_anchor_signer, not the key-path signer"
        );
        assert_eq!(anchor_witness[1], our_leaf.as_bytes());
        assert_eq!(anchor_witness[2], control_block.serialize().as_slice());

        // Wallet funding input stays a bare key-path spend via the wallet signer.
        let wallet_witness: Vec<&[u8]> = child.input[1].witness.iter().collect();
        assert_eq!(wallet_witness.len(), 1);
        assert_eq!(wallet_witness[0], &[0xBB; 64]);
    }
}
