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
//!   call — it carries the last-attempted rate and last-child-funding-inputs through the
//!   [`CpfpHandle`] state owned by the driver.
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
    Amount, FeeRate, OutPoint, Psbt, TapSighashType, Transaction, TxOut, Txid, Witness,
};
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::submitpackage::{self, SubmitPackageError};

/// Configures how the driver derives a CPFP child for a particular parent transaction.
#[derive(Debug, Clone, Copy)]
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
}

impl CpfpStrategy {
    /// Returns the `parent_fee` carried by every variant.
    pub const fn parent_fee(&self) -> Amount {
        match self {
            Self::AnchorBearing { parent_fee, .. } | Self::ParentTxCombined { parent_fee, .. } => {
                *parent_fee
            }
        }
    }
}

/// Per-parent state the driver carries between bump attempts.
#[derive(Debug, Default, Clone)]
pub struct CpfpHandle {
    /// Outpoints spent by the most recent child the driver broadcast (excluding the anchor
    /// itself). Released back to the wallet before the next bump so the same outpoints can
    /// be re-selected for the replacement child, then re-leased to whatever the new child
    /// actually consumes.
    pub last_child_inputs: Vec<OutPoint>,
    /// Package fee rate the driver last targeted. Used to skip noop bumps when the fee source
    /// hasn't moved upward.
    pub last_pkg_fee_rate: Option<FeeRate>,
    /// Txid of the child we last broadcast (for tracking / replacement). `None` before the
    /// first bump succeeds.
    pub last_child_txid: Option<Txid>,
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

/// A funded PSBT returned by a wallet handle in [`CpfpContext`].
#[derive(Debug, Clone)]
pub struct WalletFundedPsbt {
    /// PSBT with the funding input signed by the wallet, anchor input unsigned but carrying
    /// `witness_utxo` + `tap_internal_key`.
    pub psbt: Psbt,
    /// Wallet outpoints consumed by the child (not including the anchor).
    pub spent: Vec<OutPoint>,
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
    /// `replacing` is the outpoints of any prior child this rebuild supersedes (released
    /// before re-selection so they can be re-picked or replaced).
    ///
    /// See the trait-level "PSBT-signing contract" for what the returned PSBT must look
    /// like with respect to per-input `final_script_witness`.
    fn build_cpfp_child(
        &self,
        parent: &Transaction,
        strategy: CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        replacing: Option<&[OutPoint]>,
    ) -> impl std::future::Future<Output = Result<WalletFundedPsbt, String>> + Send;
}

/// Source of fee-rate estimates used to drive the package target. Same surface as
/// `bridge-exec::fees::FeeSource` but redefined here to keep the dependency graph acyclic.
///
/// In production the live source (`bridge-exec::fees::FeeSource`) is wrapped in a
/// [`CachedFeeSource`] so the bump loop reads from a hot atomic instead of hitting the
/// network per call. The tracker refreshes in the background on `refresh_interval`.
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

/// Submits a `[parent, child]` package via the configured RPC.
pub trait CpfpPackageSubmitter: Send + Sync + fmt::Debug {
    /// Forwards to bitcoind's `submitpackage` RPC; returns the typed summary.
    fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> impl std::future::Future<
        Output = Result<submitpackage::SubmitPackageSummary, SubmitPackageError>,
    > + Send;
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
        _replacing: Option<&[OutPoint]>,
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
impl CpfpPackageSubmitter for CpfpDisabled {
    fn submit_package(
        &self,
        _txs: &[Transaction],
    ) -> impl std::future::Future<
        Output = Result<submitpackage::SubmitPackageSummary, SubmitPackageError>,
    > + Send {
        async { unreachable!("CpfpDisabled::submit_package should never be called") }
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
    P: CpfpPackageSubmitter + 'static,
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
    pub package_submitter: Arc<P>,
}

impl<W, F, P> Clone for CpfpContext<W, F, P>
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpPackageSubmitter + 'static,
{
    fn clone(&self) -> Self {
        Self {
            wallet: self.wallet.clone(),
            fee_source: self.fee_source.clone(),
            anchor_input_signer: self.anchor_input_signer.clone(),
            wallet_input_signer: self.wallet_input_signer.clone(),
            max_fee_rate: self.max_fee_rate,
            package_submitter: self.package_submitter.clone(),
        }
    }
}

impl<W, F, P> Debug for CpfpContext<W, F, P>
where
    W: CpfpWallet + 'static,
    F: CpfpFeeSource + 'static,
    P: CpfpPackageSubmitter + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpfpContext")
            .field("wallet", &self.wallet)
            .field("fee_source", &self.fee_source)
            .field("anchor_input_signer", &"<closure>")
            .field("wallet_input_signer", &"<closure>")
            .field("max_fee_rate", &self.max_fee_rate)
            .field("package_submitter", &self.package_submitter)
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

/// Drives one CPFP bump attempt for `parent` under `strategy`. Idempotent against repeated
/// calls at the same target rate (skips when `target ≤ last_pkg_fee_rate`).
///
/// Returns `Ok(true)` if a package was submitted, `Ok(false)` if the bump was skipped
/// (target ≤ baseline / last rate), and the error variants of [`CpfpError`] otherwise.
///
/// Updates `handle.last_pkg_fee_rate` and `handle.last_child_inputs` on success so the next
/// call has the lease state to release.
///
/// ## Cap-and-warn at `max_fee_rate`
///
/// When the fee source reports above `ctx.max_fee_rate`, the target is clamped and a warning
/// is logged. The bump proceeds at the cap. If the fee source's target remains above the cap
/// on subsequent calls, this is steady-state — operator's `max_fee_rate` is the most they're
/// willing to pay.
///
/// ## Baseline skip
///
/// When the fee source reports `≤ bridge_protocol_floor` (2 sat/vB), no CPFP child is
/// needed — the presigned parent's own fee rate is already sufficient. Returns `Ok(false)`.
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
    P: CpfpPackageSubmitter + 'static,
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

    // ── 3. Baseline skip: presigned parent rate is enough ───────────────────
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

    // ── 4. Skip if we already bumped at this rate (eager only) ──────────────
    //
    // Reactive bumps (new block / tick / parent eviction) DO rebuild at the same rate:
    // the previous child may have been silently evicted from the mempool by a competing
    // replacement, and the only signal we get is the absence of confirmation. Rebuilding
    // at the same rate is essentially free (RBF replaces with the same fee) and keeps the
    // package alive.
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

    // ── 5. Build the child via the wallet ───────────────────────────────────
    let replacing: Option<&[OutPoint]> =
        (!handle.last_child_inputs.is_empty()).then_some(handle.last_child_inputs.as_slice());
    let funded = ctx
        .wallet
        .build_cpfp_child(parent, strategy, target, replacing)
        .await
        .map_err(CpfpError::Wallet)?;

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
    let anchor_outpoint_opt = match strategy {
        CpfpStrategy::AnchorBearing { anchor_vout, .. } => Some(OutPoint {
            txid: parent_txid,
            vout: anchor_vout,
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

    if matches!(strategy, CpfpStrategy::AnchorBearing { .. }) {
        // The wallet promised to add the anchor as a foreign UTXO; sanity-check that the
        // PSBT actually contains it before signing.
        let anchor_idx = anchor_input_idx.ok_or_else(|| {
            CpfpError::Wallet(format!(
                "wallet-built child does not contain expected anchor outpoint for parent {parent_txid}"
            ))
        })?;
        // Same skip-if-already-signed semantics as the wallet-input loop below: a wallet
        // backend that happens to hold the musig2 (anchor) key in addition to the general
        // key may pre-sign the anchor input as part of its create-and-sign API. Respect
        // that rather than overwriting.
        if psbt.inputs[anchor_idx].final_script_witness.is_none() {
            let anchor_sighash =
                compute_input_sighash(&psbt, anchor_idx).map_err(CpfpError::PsbtExtract)?;
            let anchor_sig = (ctx.anchor_input_signer)(Message::from(anchor_sighash))
                .await
                .map_err(CpfpError::AnchorSigner)?;
            let mut witness = Witness::new();
            witness.push(anchor_sig.as_ref());
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
    let summary = ctx
        .package_submitter
        .submit_package(&[parent.clone(), child])
        .await?;

    info!(
        %parent_txid,
        %child_txid,
        ?target,
        replaced = ?summary.replaced,
        "submitted CPFP package"
    );

    // ── 9. Update handle ────────────────────────────────────────────────────
    handle.last_pkg_fee_rate = Some(target);
    handle.last_child_inputs = funded.spent;
    handle.last_child_txid = Some(child_txid);

    Ok(true)
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
mod tests {
    use std::sync::Mutex;

    use bitcoin::{
        absolute,
        hashes::Hash,
        secp256k1::{Keypair, SECP256K1},
        transaction::Version,
        Address, Network, TxIn, XOnlyPublicKey,
    };

    use super::*;
    use crate::submitpackage::SubmitPackageSummary;

    // ── Test doubles ─────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct FakeFeeSource {
        rate: Mutex<Result<FeeRate, String>>,
    }
    impl FakeFeeSource {
        fn returning(rate: FeeRate) -> Self {
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

    #[derive(Debug)]
    struct FakeWallet {
        psbt_template: Mutex<Option<Psbt>>,
        spent_template: Vec<OutPoint>,
        error: Option<String>,
    }
    impl FakeWallet {
        fn returning(psbt: Psbt, spent: Vec<OutPoint>) -> Self {
            Self {
                psbt_template: Mutex::new(Some(psbt)),
                spent_template: spent,
                error: None,
            }
        }
        fn failing(msg: &str) -> Self {
            Self {
                psbt_template: Mutex::new(None),
                spent_template: Vec::new(),
                error: Some(msg.to_string()),
            }
        }
    }
    impl CpfpWallet for FakeWallet {
        fn build_cpfp_child(
            &self,
            _parent: &Transaction,
            _strategy: CpfpStrategy,
            _target_pkg_fee_rate: FeeRate,
            _replacing: Option<&[OutPoint]>,
        ) -> impl std::future::Future<Output = Result<WalletFundedPsbt, String>> + Send {
            let err = self.error.clone();
            let psbt = self.psbt_template.lock().unwrap().clone();
            let spent = self.spent_template.clone();
            async move {
                if let Some(e) = err {
                    return Err(e);
                }
                Ok(WalletFundedPsbt {
                    psbt: psbt.expect("test must seed a psbt template"),
                    spent,
                })
            }
        }
    }

    #[derive(Debug)]
    struct FakeSubmitter {
        result: Mutex<Result<SubmitPackageSummary, String>>,
        captured: Mutex<Vec<Vec<Transaction>>>,
    }
    impl FakeSubmitter {
        fn ok() -> Self {
            Self {
                result: Mutex::new(Ok(SubmitPackageSummary {
                    tx_results: Default::default(),
                    replaced: Vec::new(),
                })),
                captured: Mutex::new(Vec::new()),
            }
        }
        fn failing(reason: &str) -> Self {
            Self {
                result: Mutex::new(Err(reason.to_string())),
                captured: Mutex::new(Vec::new()),
            }
        }
    }
    impl CpfpPackageSubmitter for FakeSubmitter {
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
    }

    fn fake_input_signer_ok() -> InputSigner {
        Arc::new(|_msg: Message| {
            Box::pin(async move {
                // Schnorr signature is 64 bytes; bytes don't have to verify for unit tests of
                // the bump-loop control flow.
                let sig = Signature::from_slice(&[7u8; 64]).expect("64 bytes is a valid sig");
                Ok::<_, String>(sig)
            })
        })
    }

    fn fake_input_signer_failing(message: &'static str) -> InputSigner {
        Arc::new(move |_msg: Message| {
            let m = message.to_string();
            Box::pin(async move { Err(m) })
        })
    }

    // ── Test fixtures ────────────────────────────────────────────────────────

    fn test_keypair_and_xonly() -> (Keypair, XOnlyPublicKey) {
        let kp = Keypair::from_seckey_slice(SECP256K1, &[5u8; 32]).unwrap();
        let (x, _parity) = kp.x_only_public_key();
        (kp, x)
    }

    /// Build a synthetic parent with a keyed-Taproot anchor at vout 0.
    fn synthetic_parent(anchor_internal_key: XOnlyPublicKey, anchor_value: Amount) -> Transaction {
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
    fn synthetic_child_psbt(
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
        P: CpfpPackageSubmitter + 'static,
    {
        CpfpContext {
            wallet,
            fee_source,
            anchor_input_signer: anchor_signer,
            wallet_input_signer: wallet_signer,
            max_fee_rate,
            package_submitter: submitter,
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    const PROTOCOL_FLOOR: FeeRate = FeeRate::from_sat_per_vb_unchecked(2);

    fn anchor_strategy(anchor_key: XOnlyPublicKey) -> CpfpStrategy {
        CpfpStrategy::AnchorBearing {
            anchor_vout: 0,
            anchor_internal_key: anchor_key,
            parent_fee: Amount::from_sat(220),
        }
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
        assert_eq!(handle.last_child_inputs, wallet_funding);
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

    #[tokio::test]
    async fn cached_fee_source_retains_stale_value_when_refresh_fails() {
        // Use tokio's paused clock so we don't actually wait. Initial refresh succeeds at
        // 10 sat/vB; flip the underlying to fail; advance past the refresh interval; the
        // cache must still report the original 10 sat/vB.
        let mut underlying_rate = FakeFeeSource::returning(FeeRate::from_sat_per_vb(10).unwrap());
        // We need the underlying source to flip its result mid-flight; shadow with an Arc-Mutex.
        // Use a different fake.
        #[derive(Debug)]
        struct FlippableFeeSource {
            inner: Mutex<Result<FeeRate, String>>,
        }
        impl CpfpFeeSource for FlippableFeeSource {
            fn estimate(
                &self,
            ) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send {
                let r = self.inner.lock().unwrap().clone();
                async move { r }
            }
        }
        // Suppress unused warning
        let _ = &mut underlying_rate;

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
        // Same shape as the previous test, but underlying returns a new value mid-flight.
        #[derive(Debug)]
        struct FlippableFeeSource {
            inner: Mutex<Result<FeeRate, String>>,
        }
        impl CpfpFeeSource for FlippableFeeSource {
            fn estimate(
                &self,
            ) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send {
                let r = self.inner.lock().unwrap().clone();
                async move { r }
            }
        }

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
}
