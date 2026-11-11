//! One CPFP bump attempt: read the mempool, decide, build the child, sign it, submit it.
//!
//! Bridge presigned transactions pay a protocol-floor fee rate (`fee::FEE_RATE = 2 sat/vB`).
//! On any non-trivial network load they get evicted from the mempool before confirming. To drive
//! them to confirmation the bump builds a CPFP child that lifts the **package** (parent + child)
//! fee rate to whatever the fee source reports as the current target, and replaces the child
//! while it is below the target. Package fee accounting only: the child's per-vB rate can far
//! exceed the operator's `max_fee_rate` as long as the package average does not.
//!
//! - `decide` is the policy: a pure function from what an attempt read to what it does.
//! - [`perform_bump`] is one attempt: all the I/O around one `decide`.
//! - [`CpfpHandle`] is what an attempt keeps for the next one: the bumper's
//!   [`State`](CpfpBumper::State), which `TxDriver` keeps between attempts.
//! - [`CpfpContext`] bundles the dependencies of a bump and implements [`CpfpBumper`] for
//!   `TxDriver`.
//!
//! The ladder is the run of attempts for one parent. It does not retry: each [`perform_bump`] is
//! one attempt, priced from the market of the moment, and the driver calls again on the next
//! trigger.
//!
//! ## `max_fee_rate`
//!
//! `max_fee_rate` is a hard limit on what a package pays. The target clamps to it, and a
//! replacement that the mempool rules would price above it is not built. A parent can therefore
//! stay below the market. That state counts in the metrics of
//! [`observability`] and logs at debug on each attempt.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use bitcoin::{Amount, FeeRate, Transaction, Txid};
use btc_tracker::cpfp::{BumpOutcome, CpfpBumper, CpfpStrategy};
use operator_wallet::{IncumbentChild, ReplacedChild};
use tracing::{debug, info, trace, warn};

use super::{
    decide::{BumpAction, BumpInputs, Decision, decide},
    errors::{CpfpError, CpfpWalletError},
    handle::{CpfpHandle, HeldChild},
    interfaces::{CpfpMempool, CpfpWallet, InputSigner, MempoolChild, ParentProbe},
    observability::{self, CapReason},
    sign::sign_child,
};
use crate::fees::{FeeSource, FeeTargetPolicy, SAT_PER_KWU_PER_SAT_PER_VB};

/// Everything one bump needs. Implements [`CpfpBumper`] for `TxDriver`.
pub struct CpfpContext {
    /// Wallet that constructs the child PSBT. The PSBT comes back **unsigned**, and
    /// [`perform_bump`] signs it through [`CpfpWallet::sign_owned_inputs`] and
    /// [`Self::wallet_input_signer`].
    pub wallet: Arc<dyn CpfpWallet>,
    /// Source of the current package fee-rate target.
    pub fee_source: Arc<dyn FeeSource>,
    /// Signs the input of a keyed-anchor child: the protocol-key input that the parent's CPFP
    /// anchor pins to. Bound to the operator's musig2-signer pubkey in production (see
    /// [`InputSigner`] doc). Not called for a child that spends an owned output.
    pub anchor_input_signer: InputSigner,
    /// Signs the **script-path anchor input** of a multi-anchor child (`contest`,
    /// `bridge_proof_timeout`).
    ///
    /// Distinct from [`Self::anchor_input_signer`] because a script-path spend satisfies the leaf
    /// directly: the signature must be made with the raw key, *not* BIP-341 tap-tweaked. In the
    /// bridge this is the operator's musig2 signer used untweaked — the same key and mode
    /// `publish_contest` uses to sign the contest transaction's own input.
    pub multi_anchor_signer: InputSigner,
    /// Signs each wallet input that the wallet signer leaves to the ladder. Bound to the
    /// operator's general-wallet-signer pubkey in production. Called once per such input.
    pub wallet_input_signer: InputSigner,
    /// Fee settings of the operator.
    pub policy: FeeTargetPolicy,
    /// Submits `[parent, child]` packages and reads what the mempool holds for a parent.
    pub mempool: Arc<dyn CpfpMempool>,
}

impl fmt::Debug for CpfpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CpfpContext")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl CpfpBumper for CpfpContext {
    type State = CpfpHandle;

    /// Runs one attempt and classifies its result.
    ///
    /// A bump error carries what the driver needs to know: whether the parent can ever carry a
    /// child. The probe of the attempt carries the other fact: whether a mempool holds the parent.
    async fn bump(
        &self,
        parent: &Transaction,
        strategy: &CpfpStrategy,
        handle: &mut CpfpHandle,
    ) -> BumpOutcome {
        let parent_txid = parent.compute_txid();
        let attempt = perform_bump(self, parent, strategy, handle).await;

        let parent_in_mempool = attempt.parent_in_mempool;
        match attempt.outcome() {
            Ok(outcome) => outcome,
            Err(CpfpError::Wallet(e @ CpfpWalletError::Unbumpable(_))) => {
                // `warn!`, not `error!`: the driver stops the bumps for this parent, and the bare
                // paths keep carrying it.
                warn!(
                    %parent_txid,
                    error = %e,
                    "parent cannot carry a CPFP child; stopping the bumps for it"
                );
                BumpOutcome::Unbumpable
            }
            // A transaction that conflicts with the parent is in the mempool, and the parent is
            // not, whatever the probe read before the submission.
            Err(e) if e.is_replacement_contention_for(&parent_txid) => BumpOutcome::NoPackage,
            Err(e) => {
                if e.replacement_rejection().is_none() {
                    warn!(%parent_txid, error = %e, "CPFP bump failed; will retry on next trigger");
                }
                BumpAttempt::no_package(parent_in_mempool)
            }
        }
    }
}

/// What one attempt read about the parent, and what it did.
#[derive(Debug)]
pub struct BumpAttempt {
    /// Whether the probe of this attempt read the parent in the mempool.
    parent_in_mempool: bool,
    /// What the attempt did. A skip is [`BumpOutcome::NoPackage`].
    result: Result<BumpOutcome, CpfpError>,
}

impl BumpAttempt {
    /// What an attempt with no package reports: a parent in the mempool reached the network,
    /// whatever else the attempt did.
    const fn no_package(parent_in_mempool: bool) -> BumpOutcome {
        if parent_in_mempool {
            BumpOutcome::ParentIsLive
        } else {
            BumpOutcome::NoPackage
        }
    }

    /// The result of the attempt. A skip with the parent in the mempool reports
    /// [`BumpOutcome::ParentIsLive`].
    pub fn outcome(self) -> Result<BumpOutcome, CpfpError> {
        self.result.map(|outcome| match outcome {
            BumpOutcome::NoPackage => Self::no_package(self.parent_in_mempool),
            outcome => outcome,
        })
    }
}

/// Brings `handle` up to date with `probe`, and adopts a live child that the handle does not
/// know.
///
/// A process restart empties the handle, and so does a reorg that wakes a mined parent, while the
/// child stays in the mempool. The wallet hides the inputs of that child once a sync observes it,
/// so without adoption a small wallet cannot fund the replacement, and without a lease a
/// concurrent duty can select those inputs before a sync.
///
/// Returns whether the live child is proven foreign: the wallet owns no input of it. A failed
/// lookup proves nothing, so a later attempt reads the child again.
async fn reconcile(
    ctx: &CpfpContext,
    parent_txid: Txid,
    probe: Option<&ParentProbe>,
    handle: &mut CpfpHandle,
) -> bool {
    let Some(unknown) = handle.observe(probe) else {
        return false;
    };
    let inputs = match ctx.mempool.child_inputs(unknown).await {
        Ok(inputs) => inputs,
        Err(e) => {
            warn!(%parent_txid, child_txid = %unknown, error = %e, "could not read a live child");
            return false;
        }
    };
    match ctx.wallet.adopt_child(parent_txid, inputs).await {
        Some(lease) => {
            info!(%parent_txid, child_txid = %unknown, "adopted a live CPFP child");
            handle.accepted = Some(HeldChild {
                txid: unknown,
                lease,
            });
            handle.candidate = None;
            false
        }
        None => {
            handle.demote_accepted();
            true
        }
    }
}

/// Drives one CPFP bump attempt for `parent` under `strategy`.
///
/// Returns what the attempt read and did. Every attempt reads the mempool, and then the fee source,
/// and `decide` takes it from there.
///
/// ## The probe
///
/// The probe and the adoption of a live child run first, because neither needs a price: a fee
/// outage must not leave the inputs of a live child without a lease.
///
/// A failed probe does not stop a first child: the submission is the authority on whether a
/// package is acceptable. With a live child on the handle it skips the build. The probe is not a
/// lock. Two builders can read an empty slot in the same instant and both build. That race is
/// bounded to one round, because the loser observes the winner on the next trigger.
///
/// ## The handle
///
/// A failed signature drops the new lease, because nothing reached the network. The handle then
/// records the submission, see `CpfpHandle::record_submission`. The accepted slot changes only on
/// a success result or a probe, so the incumbent keeps its inputs through every failure.
pub async fn perform_bump(
    ctx: &CpfpContext,
    parent: &Transaction,
    strategy: &CpfpStrategy,
    handle: &mut CpfpHandle,
) -> BumpAttempt {
    let parent_txid = parent.compute_txid();

    let probe = ctx
        .mempool
        .probe(parent_txid)
        .await
        .inspect_err(|e| warn!(%parent_txid, error = %e, "CPFP probe failed"))
        .ok();
    let foreign_child = reconcile(ctx, parent_txid, probe.as_ref(), handle).await;

    let result = act(ctx, parent, strategy, handle, probe).await;

    // No live child spends the inputs of a child that lost to a foreign one, so the wallet can
    // use them. `NoPackage` here is the `AboveCap` refusal or the `StandDown` behind the foreign
    // child; a failed build keeps them, and that does no harm: the next build can spend them. A
    // child of ours keeps its lease: a release lets a concurrent duty double-spend the inputs and
    // evict it. The design review of 2026-11-02 names this safe only when the probe proved the
    // output unspent and the rejection followed, which the `foreign_child` read is.
    if foreign_child && matches!(result, Ok(BumpOutcome::NoPackage)) {
        handle.candidate = None;
    }

    BumpAttempt {
        parent_in_mempool: matches!(probe, Some(ParentProbe::NoChild | ParentProbe::Child(_))),
        result,
    }
}

/// Decides one attempt on what `probe` read, and carries the decision out.
///
/// A separate function so that an early return with `?` still reaches the end of
/// [`perform_bump`].
async fn act(
    ctx: &CpfpContext,
    parent: &Transaction,
    strategy: &CpfpStrategy,
    handle: &mut CpfpHandle,
    probe: Option<ParentProbe>,
) -> Result<BumpOutcome, CpfpError> {
    let parent_txid = parent.compute_txid();
    let parent_vbytes = u64::try_from(parent.vsize()).expect("tx vsize fits in u64");
    let estimate = ctx.fee_source.next_block_rate().await?;

    // `decide` applies the same rule; the read is skipped when it cannot matter.
    let node_min = match probe {
        Some(ParentProbe::Absent) => ctx
            .mempool
            .min_fee_rate()
            .await
            .inspect_err(|e| warn!(%parent_txid, error = %e, "could not read the mempool minimum"))
            .ok(),
        _ => None,
    };

    let Decision {
        target,
        wanted,
        action,
    } = decide(BumpInputs {
        estimate,
        policy: ctx.policy,
        node_min,
        parent_vbytes,
        parent_fee: strategy.parent_fee,
        probe,
        child_may_be_live: handle.accepted.is_some() || handle.candidate.is_some(),
    });

    let mut held_back = (wanted > target).then_some(CapReason::Target);
    if held_back.is_some() {
        // Every attempt of a capped parent lands here, so this stays at debug; the metric in
        // `record_capped_attempt` carries the signal.
        debug!(
            %parent_txid,
            ?wanted,
            cap = ?target,
            "package target exceeds max_fee_rate; clamping to the cap"
        );
    }

    let outcome = match action {
        BumpAction::ParentSuffices => {
            // Quiet: this fires on every tick for every parent in a quiet mempool.
            trace!(%parent_txid, ?target, parent_fee = %strategy.parent_fee, "parent fee alone meets the target");
            Ok(BumpOutcome::NoPackage)
        }
        BumpAction::AwaitProbe => {
            warn!(%parent_txid, ?target, "skipping the build until a probe reads the live child");
            Ok(BumpOutcome::NoPackage)
        }
        BumpAction::NodeMinAboveCap => {
            warn!(%parent_txid, ?node_min, cap = ?target, "the node minimum is above max_fee_rate; no package can enter");
            Ok(BumpOutcome::NoPackage)
        }
        BumpAction::StandDown => {
            debug!(%parent_txid, ?target, ?probe, "a live child meets the target; skipping");
            Ok(BumpOutcome::NoPackage)
        }
        BumpAction::Build { incumbent } => {
            match build_and_submit(ctx, parent, strategy, handle, target, incumbent).await {
                Err(CpfpError::Wallet(e @ CpfpWalletError::AboveCap { .. })) => {
                    warn!(
                        %parent_txid,
                        ?target,
                        ?incumbent,
                        error = %e,
                        "a child needs more than max_fee_rate; not building"
                    );
                    held_back = Some(CapReason::ChildRefused);
                    Ok(BumpOutcome::NoPackage)
                }
                outcome => outcome,
            }
        }
    };

    if let Some(reason) = held_back {
        observability::record_capped_attempt(strategy.deadline, reason);
    }
    outcome
}

/// Builds, signs, and submits one child at `target`, and records the result on `handle`.
async fn build_and_submit(
    ctx: &CpfpContext,
    parent: &Transaction,
    strategy: &CpfpStrategy,
    handle: &mut CpfpHandle,
    target: FeeRate,
    incumbent: Option<MempoolChild>,
) -> Result<BumpOutcome, CpfpError> {
    let parent_txid = parent.compute_txid();
    let prior = handle.prior_children();
    let replaced = ReplacedChild {
        prior: &prior,
        incumbent: incumbent.map(|child| IncumbentChild {
            fee: child.fee,
            vbytes: child.vbytes,
        }),
    };

    let funded = match ctx
        .wallet
        .build_cpfp_child(parent, strategy, target, ctx.policy.max_fee_rate, replaced)
        .await
    {
        Ok(funded) => funded,
        Err(e) => {
            if matches!(e, CpfpWalletError::Transient(_)) {
                refresh_wallet(ctx, parent_txid).await;
            }
            return Err(e.into());
        }
    };

    let child_fee = funded
        .psbt
        .fee()
        .map_err(|e| CpfpError::MalformedChild(format!("fee: {e}")))?;

    // A failure here drops the new lease, which returns its inputs. Nothing reached the network.
    let child = sign_child(ctx, strategy, funded.psbt).await?;
    let child_txid = child.compute_txid();
    let child_vbytes = u64::try_from(child.vsize()).expect("tx vsize fits in u64");
    let parent_vbytes = u64::try_from(parent.vsize()).expect("tx vsize fits in u64");

    let submission = ctx.mempool.submit_package(&[parent.clone(), child]).await;
    let held = HeldChild {
        txid: child_txid,
        lease: funded.lease,
    };
    handle.record_submission(held, submission.as_ref().map(|_| ()));

    let summary = match submission {
        Ok(summary) => summary,
        Err(e) => {
            // A missing input means that the view of the wallet is behind the chain. The new
            // child cannot enter any mempool, and a lease on the spent input would steer the next
            // build to that input again, so the candidate goes. The accepted child stays: the
            // node names no input, and the incumbent can be live; the next probe demotes it if it
            // is gone.
            if e.is_missing_inputs() {
                handle.candidate = None;
                refresh_wallet(ctx, parent_txid).await;
            }
            if let (Some(rejection), Some(child)) = (e.replacement_rejection(), incumbent) {
                warn!(
                    %parent_txid,
                    ?target,
                    ?rejection,
                    incumbent = ?child,
                    "the mempool refused a replacement while the parent is below its target"
                );
            }
            return Err(e.into());
        }
    };

    info!(
        %parent_txid,
        %child_txid,
        parent = observability::parent_label(strategy.deadline),
        %child_fee,
        package_rate = ?package_rate(strategy.parent_fee + child_fee, parent_vbytes + child_vbytes),
        ?target,
        replaced = ?summary.replaced,
        "submitted CPFP package"
    );
    observability::record_accepted_child(strategy.deadline, child_fee);

    Ok(BumpOutcome::Submitted)
}

/// The rate that a package of `fee` over `vbytes` pays. A package holds at least one non-empty
/// transaction, so `vbytes` is not zero.
fn package_rate(fee: Amount, vbytes: u64) -> FeeRate {
    FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(SAT_PER_KWU_PER_SAT_PER_VB) / vbytes)
}

/// Asks the wallet for a fresh view. The next trigger retries the bump, so a failure here only
/// costs that attempt.
async fn refresh_wallet(ctx: &CpfpContext, parent_txid: Txid) {
    if let Err(e) = ctx.wallet.refresh().await {
        warn!(%parent_txid, error = %e, "wallet refresh after a failed bump failed");
    }
}
