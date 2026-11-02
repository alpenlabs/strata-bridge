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
//! - [`CpfpHandle`] is what an attempt keeps for the next one. `TxDriver` carries it as an opaque
//!   [`BumpState`].
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
//! [`observability`](super::observability) and logs at debug on each attempt.

use std::{fmt, num::NonZeroU64, sync::Arc};

use async_trait::async_trait;
use bitcoin::{
    Amount, FeeRate, Psbt, ScriptBuf, TapSighashType, Transaction, TxOut, Txid, Witness,
    secp256k1::{Message, schnorr::Signature},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash},
};
use btc_tracker::cpfp::{BumpOutcome, BumpState, CpfpBumper, CpfpStrategy};
use operator_wallet::{FundingInput, IncumbentChild, Lease, PriorChild, ReplacedChild};
use strata_bridge_primitives::cpfp::{ChildSigner, ChildWitness};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

use super::{
    SAT_PER_KWU_PER_SAT_PER_VB,
    observability::{self, CapReason},
    submitpackage::{ReplacementRejection, SubmitPackageError, SubmitPackageSummary},
};
use crate::fees::{FeeSource, FeeSourceError, FeeTargetPolicy};

/// A child that this operator built or adopted, and the lease on its wallet inputs.
#[derive(Debug, Clone)]
struct HeldChild {
    /// Txid of the child.
    txid: Txid,
    /// The wallet frees the inputs when the last clone of this value drops.
    lease: Arc<dyn FundingLease>,
}

/// Per-parent state the driver carries between bump attempts.
///
/// The handle holds leases and identities only. The fee that a replacement must beat comes from
/// the mempool on every attempt.
///
/// Every path that stops the bumps for a parent frees the inputs by dropping the handle, and no
/// path needs an explicit release call. The driver clones the handle to run a bump without the
/// entries lock held. The clone keeps the leases alive for the length of the bump.
#[derive(Debug, Default, Clone)]
pub struct CpfpHandle {
    /// The child that the mempool holds, by a success result or by a probe. Its lease stays until
    /// a mempool accepts its replacement or a probe shows that the child is gone.
    accepted: Option<HeldChild>,
    /// The most recent child with no known place in a mempool: one with an unknown submission
    /// result, or one that left this mempool. It can be in another mempool, so its inputs stay
    /// held, and the next build can spend them again. One slot: a newer such child takes it over,
    /// and the older lease drops. A rejection of a later child, a demotion of the accepted child
    /// and a promotion of the candidate also free the inputs, so a child in another mempool can
    /// lose them to another duty. The design accepts that: such a child is in no mempool this node
    /// sees, and the inputs cannot stay held on a guess.
    candidate: Option<HeldChild>,
}

impl CpfpHandle {
    /// Txid of the child that the mempool holds, as far as this handle knows.
    pub fn accepted_txid(&self) -> Option<Txid> {
        self.accepted.as_ref().map(|child| child.txid)
    }

    /// The children whose inputs the next child may spend again. Those of [`Self::accepted`]
    /// conflict with it, which a replacement must do. Those of [`Self::candidate`] are spent by no
    /// child in this mempool.
    fn prior_children(&self) -> Vec<PriorChild<'_>> {
        [&self.accepted, &self.candidate]
            .into_iter()
            .flatten()
            .map(|child| PriorChild {
                txid: child.txid,
                lease: child.lease.lease(),
                inputs: child.lease.inputs(),
            })
            .collect()
    }

    /// Moves [`Self::accepted`] to [`Self::candidate`]: the mempool does not hold that child.
    fn demote_accepted(&mut self) {
        if let Some(gone) = self.accepted.take() {
            self.candidate = Some(gone);
        }
    }

    /// Applies a probe. Returns the live child when the handle does not know it.
    ///
    /// A `None` probe teaches nothing, so it changes nothing.
    fn observe(&mut self, probe: Option<&ParentProbe>) -> Option<Txid> {
        let is = |held: &Option<HeldChild>, txid| held.as_ref().is_some_and(|c| c.txid == txid);
        match probe? {
            ParentProbe::Absent | ParentProbe::NoChild => {
                self.demote_accepted();
                None
            }
            ParentProbe::Child(child) if is(&self.accepted, child.txid) => None,
            ParentProbe::Child(child) if is(&self.candidate, child.txid) => {
                self.accepted = self.candidate.take();
                None
            }
            ParentProbe::Child(child) => Some(child.txid),
        }
    }

    /// Records what became of `child` after its submission.
    ///
    /// - A success makes `child` the accepted child, and every older lease drops.
    /// - An unknown result keeps `child` as the candidate.
    /// - A rejection drops `child`: the node did not take it, so it did not relay it. The candidate
    ///   drops too, because the rejection can come from an input of the candidate, and that input
    ///   would repeat the rejection on every trigger. The next build reselects from what the wallet
    ///   lists. The accepted child stays.
    fn record_submission(&mut self, child: HeldChild, result: Result<(), &SubmitPackageError>) {
        match result {
            Ok(()) => {
                self.accepted = Some(child);
                self.candidate = None;
            }
            Err(SubmitPackageError::Rpc(_)) => self.candidate = Some(child),
            Err(SubmitPackageError::Rejected { .. }) => self.candidate = None,
        }
    }
}

/// A mempool query could not complete.
#[derive(Debug, Clone, Error)]
#[error("mempool: {0}")]
pub struct MempoolError(pub String);

/// An input signer could not produce a signature.
///
/// The bump skips and the next trigger retries. A signer fault does not stop the bumps for a
/// parent, whichever signer it comes from.
#[derive(Debug, Clone, Error)]
#[error("{0}")]
pub struct SignerError(pub String);

/// Why a wallet could not build a CPFP child.
///
/// The cases lead to different driver behaviour, so the boundary reports which one it is rather
/// than one message that the driver has to read.
#[derive(Debug, Error)]
pub enum CpfpWalletError {
    /// The parent cannot carry a child, whatever the wallet does. Its anchor is not where the
    /// strategy says, or the wallet cannot spend it. A signed parent does not change shape, so
    /// every later attempt fails at the same step.
    #[error("parent cannot carry a child: {0}")]
    Unbumpable(String),
    /// The child lifts the package past the cap.
    #[error("the package needs a fee of {needed}, past the cap of {ceiling}")]
    AboveCap {
        /// Fee of the (parent, child) package with the replacement.
        needed: Amount,
        /// Most that the package may pay at its size.
        ceiling: Amount,
    },
    /// The wallet could not fund a child now. Funds arrive, the chain moves, and a later
    /// attempt can pass.
    #[error("{0}")]
    Transient(String),
}

/// Errors produced by [`perform_bump`].
#[derive(Debug, Error)]
pub enum CpfpError {
    /// The fee source lookup failed. The bump is skipped; the next trigger will retry.
    #[error("{0}")]
    FeeSource(#[from] FeeSourceError),
    /// The wallet could not build the child.
    #[error("wallet: {0}")]
    Wallet(#[from] CpfpWalletError),
    /// The anchor input signer returned an error. The bump is skipped; the next trigger
    /// will retry.
    #[error("anchor signer: {0}")]
    AnchorSigner(SignerError),
    /// A signer of the wallet inputs returned an error. The bump is skipped; the next trigger
    /// will retry.
    #[error("wallet input signer: {0}")]
    WalletSigner(SignerError),
    /// `submitpackage` returned a non-success outcome. Logged + bump skipped.
    #[error("submit_package: {0}")]
    SubmitPackage(#[from] SubmitPackageError),
    /// The wallet returned a child that has no fee, no anchor, or no valid sighash, or a child
    /// that does not extract after signing.
    #[error("malformed child: {0}")]
    MalformedChild(String),
}

impl CpfpError {
    /// Which replacement rule the node applied to reject a package member.
    pub fn replacement_rejection(&self) -> Option<ReplacementRejection> {
        match self {
            Self::SubmitPackage(e) => e.replacement_rejection(),
            _ => None,
        }
    }

    /// Whether the transaction `txid` itself lost a replacement race. See
    /// [`SubmitPackageError::is_replacement_contention_for`].
    pub fn is_replacement_contention_for(&self, txid: &Txid) -> bool {
        matches!(self, Self::SubmitPackage(e) if e.is_replacement_contention_for(txid))
    }
}

/// Wallet inputs that one CPFP child holds.
///
/// The wallet frees the inputs when this value drops. The handle keeps the value for as long as
/// the child can be live, so that no other duty selects the inputs and evicts the child. A wallet
/// sync that observes the child prunes its record in the lease set, and this value still carries
/// the inputs for the next rebuild.
///
/// A trait rather than [`operator_wallet::Lease`] so that tests can observe the drop.
pub trait FundingLease: Send + Sync + fmt::Debug {
    /// The inputs that this lease holds, with the outputs they spend. The anchor input is not
    /// one of them, unless the output that the child spends belongs to the wallet.
    fn inputs(&self) -> &[FundingInput];

    /// The wallet lease behind this value. Selection for a replacement looks past it.
    fn lease(&self) -> &Lease;
}

/// A funded PSBT returned by [`CpfpWallet::build_cpfp_child`].
#[derive(Debug, Clone)]
pub struct WalletFundedPsbt {
    /// The unsigned child PSBT. Every input carries `witness_utxo`: the fee of the child and
    /// the sighash of each input read the spent outputs.
    pub psbt: Psbt,
    /// Holds the wallet inputs that the child consumes.
    pub lease: Arc<dyn FundingLease>,
}

/// What the ladder needs from the wallet: the next CPFP child, a lease on the inputs of a child
/// that the handle does not know, and a signature for each input that a wallet signer holds the
/// key for.
///
/// Building and signing are separate so that the wallet stays free while a signer waits for a
/// signature. [`perform_bump`] signs every other input itself: the anchor through
/// [`CpfpContext::anchor_input_signer`] or [`CpfpContext::multi_anchor_signer`], and a wallet input
/// the signer does not sign through [`CpfpContext::wallet_input_signer`].
#[async_trait]
pub trait CpfpWallet: Send + Sync {
    /// Builds an unsigned CPFP child for `parent` under `strategy`, targeting
    /// `target_pkg_fee_rate` on the (parent, child) package.
    ///
    /// `max_package_rate` is a hard limit: a child past it is [`CpfpWalletError::AboveCap`].
    ///
    /// `replaced` names the live child that the new one must outbid, and the earlier children
    /// whose inputs stay available to the build. A lease over those inputs stays valid across the
    /// call: the handle drops it once a mempool accepts the new child.
    async fn build_cpfp_child(
        &self,
        parent: &Transaction,
        strategy: &CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        max_package_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<WalletFundedPsbt, CpfpWalletError>;

    /// Takes a lease on those of `inputs` that belong to this wallet. `None` when no input does,
    /// which means that the child belongs to another operator.
    ///
    /// `inputs` are every input of a live child of `parent`, with the outputs they spend.
    async fn adopt_child(
        &self,
        parent: Txid,
        inputs: Vec<FundingInput>,
    ) -> Option<Arc<dyn FundingLease>>;

    /// Brings the view of the wallet up to date with the node.
    ///
    /// Selection reads that view, so a bump that the view failed calls this before the next
    /// attempt: a funding failure can hide a top-up, and a rejected input is spent. The call takes
    /// the exclusive wallet guard, and no bump holds a wallet guard when it calls this.
    async fn refresh(&self) -> Result<(), CpfpWalletError>;

    /// Signs the inputs of `tx` at `input_indices` that the wallet signer holds a key for.
    /// Returns one entry per index, `None` for an input that the ladder must sign itself.
    ///
    /// `prevouts[i]` is the output spent by `tx.input[i]`.
    async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, SignerError>;
}

/// Boxed future returned by an [`InputSigner`]; pinned + Send so it can cross a tokio task
/// boundary.
pub type InputSignFut =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Signature, SignerError>> + Send>>;

/// Signs one Taproot input by computing a Schnorr signature over the caller-supplied sighash.
///
/// A [`CpfpContext`] holds one signer per key and mode:
///
/// - [`CpfpContext::anchor_input_signer`] signs a keyed anchor with the key that built it, tweaked
///   for a key-path spend. In the bridge this is the operator's musig2-signer pubkey, which also
///   serves as its watchtower key.
/// - [`CpfpContext::multi_anchor_signer`] signs a multi-anchor leaf with the same key, untweaked
///   for a script-path spend.
/// - [`CpfpContext::wallet_input_signer`] signs each funding input that the wallet's own signer
///   does not sign, tweaked for a key-path spend. In the bridge this is the general-wallet pubkey
///   that secret-service holds. A Fireblocks vault signs every funding input, so this signer does
///   not run there.
pub type InputSigner = Arc<dyn Fn(Message) -> InputSignFut + Send + Sync>;

/// A mempool child of a parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolChild {
    /// Txid of the child.
    pub txid: Txid,
    /// Absolute fee of the child alone. A replacement must beat it.
    pub fee: Amount,
    /// Size of the child alone. A replacement must beat its own fee rate.
    pub vbytes: NonZeroU64,
    /// Rate that the child and its unconfirmed ancestors pay together.
    pub pkg_fee_rate: FeeRate,
}

/// What the mempool holds for a parent.
///
/// Every bump parent is a v3 transaction, so TRUC gives it one child, on any of its outputs. The
/// probe therefore reads the descendants of the parent and not the output that this operator
/// would spend. A child on another output blocks a new child in the same way as a child on the
/// same output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentProbe {
    /// The mempool does not hold the parent. A parent that never entered, a parent that the node
    /// evicted, and a parent that confirmed all read this way.
    Absent,
    /// The mempool holds the parent, and the parent has no child.
    NoChild,
    /// The mempool holds the parent and this child of it.
    Child(MempoolChild),
}

/// The bitcoind mempool operations that a bump needs.
#[async_trait]
pub trait CpfpMempool: Send + Sync {
    /// Forwards to bitcoind's `submitpackage` RPC; returns the typed summary.
    async fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> Result<SubmitPackageSummary, SubmitPackageError>;

    /// Reports what the mempool holds for `parent`.
    async fn probe(&self, parent: Txid) -> Result<ParentProbe, MempoolError>;

    /// Reads every input of the mempool transaction `child`, with the output it spends.
    async fn child_inputs(&self, child: Txid) -> Result<Vec<FundingInput>, MempoolError>;

    /// The lowest fee rate at which this node admits a package.
    async fn min_fee_rate(&self) -> Result<FeeRate, MempoolError>;
}

/// Everything [`decide`] reads.
#[derive(Debug, Clone, Copy)]
struct BumpInputs {
    /// Next-block rate of the fee source.
    estimate: FeeRate,
    /// Fee settings of the operator.
    policy: FeeTargetPolicy,
    /// [`CpfpMempool::min_fee_rate`] when the attempt read it. An attempt reads it only for an
    /// absent parent, to spare the RPC. The rule itself is in `decide`.
    node_min: Option<FeeRate>,
    /// Size of the parent.
    parent_vbytes: u64,
    /// Fee that the parent pays.
    parent_fee: Amount,
    /// The probe of this attempt. `None` when it failed.
    probe: Option<ParentProbe>,
    /// Whether the handle records a child that can be in a mempool.
    child_unresolved: bool,
}

/// What one attempt does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BumpAction {
    /// The parent meets the target alone. A child would only pay for its own vbytes, and a child
    /// asked to cover nothing can select no funding input and fail on a below-dust drain.
    ParentSuffices,
    /// A live child meets the target.
    StandDown,
    /// The probe failed and the handle records a child that can be live. The fee of that child is
    /// unknown, so a build cannot be priced to replace it, and each refused build costs a signing
    /// round and, through the rejection, the lease of a candidate.
    AwaitProbe,
    /// The node holds no parent and asks more than the cap for a package. A package cannot enter,
    /// so an attempt spends no lease and no signing round on one.
    NodeMinAboveCap,
    /// Build a child. It must outbid `incumbent` when there is one.
    Build {
        /// The live child that the new child replaces.
        incumbent: Option<MempoolChild>,
    },
}

/// What [`decide`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decision {
    /// Package rate of this attempt. Never above the cap.
    target: FeeRate,
    /// What the target would be with no cap.
    wanted: FeeRate,
    /// What the attempt does.
    action: BumpAction,
}

/// Decides one bump attempt.
///
/// ## Target
///
/// The target starts at the next-block estimate: a CPFP child must confirm in the next block.
///
/// The premium raises the estimate (a percentage, rounded up in sat/kwu) and
/// `min_package_fee_rate` floors the result. The floor bounds the package rate, and the child pays
/// the whole shortfall, so the package always lands at or above the floor. Sources report raw
/// market estimates; both settings are policy of this consumer.
///
/// `node_min` raises the target only while the node does not hold the parent. A package with
/// the parent in it must clear that rate as a package, or the node refuses it. With the parent in
/// the mempool, the node judges the child alone, and the child's own rate clears it. The target
/// therefore stays independent of the local mempool wherever that is possible.
///
/// The cap applies last, to all of the above.
///
/// ## Action
///
/// A parent that meets the target alone needs nothing, whatever the mempool holds. Otherwise, a
/// live child at the target ends the attempt, and a live child under the target or an empty slot
/// gets a new child. A failed probe with a child on the handle waits for the next trigger.
fn decide(inputs: BumpInputs) -> Decision {
    let BumpInputs {
        estimate,
        policy,
        node_min,
        parent_vbytes,
        parent_fee,
        probe,
        child_unresolved,
    } = inputs;

    let node_min = node_min.filter(|_| probe == Some(ParentProbe::Absent));
    let wanted = policy
        .wanted(estimate)
        .max(node_min.unwrap_or(FeeRate::ZERO));
    let target = wanted.min(policy.max_fee_rate);

    let parent_suffices = target
        .fee_vb(parent_vbytes)
        .is_some_and(|needed| parent_fee >= needed);
    let action = match probe {
        _ if parent_suffices => BumpAction::ParentSuffices,
        Some(ParentProbe::Absent) if node_min > Some(policy.max_fee_rate) => {
            BumpAction::NodeMinAboveCap
        }
        Some(ParentProbe::Child(child)) if child.pkg_fee_rate >= target => BumpAction::StandDown,
        Some(ParentProbe::Child(child)) => BumpAction::Build {
            incumbent: Some(child),
        },
        None if child_unresolved => BumpAction::AwaitProbe,
        None | Some(ParentProbe::Absent | ParentProbe::NoChild) => {
            BumpAction::Build { incumbent: None }
        }
    };

    Decision {
        target,
        wanted,
        action,
    }
}

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
    /// Runs one attempt and classifies its result.
    ///
    /// A bump error carries what the driver needs to know: whether the parent can ever carry a
    /// child. The probe of the attempt carries the other fact: whether a mempool holds the parent.
    async fn bump(
        &self,
        parent: &Transaction,
        strategy: &CpfpStrategy,
        state: &mut BumpState,
    ) -> BumpOutcome {
        let parent_txid = parent.compute_txid();
        let mut handle = state.get::<CpfpHandle>().cloned().unwrap_or_default();
        let attempt = perform_bump(self, parent, strategy, &mut handle).await;
        // The handle goes back whatever the result: a submission with an unknown result leaves
        // a lease that the next attempt needs.
        *state = BumpState::new(handle);

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

    /// The result of the attempt. See [`Self::no_package`] for a skip.
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
        child_unresolved: handle.accepted.is_some() || handle.candidate.is_some(),
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

/// Signs every input of the unsigned child `psbt` and extracts the transaction.
///
/// - A spend signed by the protocol key is one anchor input, signed by the signer of its witness
///   kind, plus wallet funding inputs.
/// - An owned spend has only operator-controlled inputs: the output of the parent and wallet
///   funding inputs.
///
/// The wallet signer goes first for the wallet inputs. An input it holds no key for goes through
/// `wallet_input_signer`. A sighash commits to no other witness, so the order does not matter.
async fn sign_child(
    ctx: &CpfpContext,
    strategy: &CpfpStrategy,
    mut psbt: Psbt,
) -> Result<Transaction, CpfpError> {
    let spend = &strategy.spend;
    let prevouts = prevouts_of(&psbt).map_err(CpfpError::MalformedChild)?;
    let anchor_idx = (spend.signer() == ChildSigner::Protocol)
        .then(|| {
            psbt.unsigned_tx
                .input
                .iter()
                .position(|input| input.previous_output == spend.outpoint())
                .ok_or_else(|| {
                    CpfpError::MalformedChild("the child does not spend the anchor".to_string())
                })
        })
        .transpose()?;

    if let Some(anchor_idx) = anchor_idx {
        let witness = match spend.witness() {
            // Key-path: sign the tweaked output key, witness is the bare signature.
            ChildWitness::KeyPath => {
                let sighash = key_path_sighash(&psbt.unsigned_tx, anchor_idx, &prevouts)
                    .map_err(CpfpError::MalformedChild)?;
                let sig = (ctx.anchor_input_signer)(Message::from(sighash))
                    .await
                    .map_err(CpfpError::AnchorSigner)?;
                let mut witness = Witness::new();
                witness.push(sig.as_ref());
                witness
            }
            // Script-path: the sighash commits to the leaf, the signature is untweaked,
            // and the witness carries the leaf script and control block after it.
            ChildWitness::ScriptPath {
                leaf_script,
                control_block,
            } => {
                let sighash =
                    script_path_sighash(&psbt.unsigned_tx, anchor_idx, &prevouts, leaf_script)
                        .map_err(CpfpError::MalformedChild)?;
                let sig = (ctx.multi_anchor_signer)(Message::from(sighash))
                    .await
                    .map_err(CpfpError::AnchorSigner)?;
                let mut witness = Witness::new();
                witness.push(sig.as_ref());
                witness.push(leaf_script.to_bytes());
                witness.push(control_block.serialize());
                witness
            }
        };
        psbt.inputs[anchor_idx].final_script_witness = Some(witness);
    }

    let wallet_input_idxs: Vec<usize> = (0..psbt.inputs.len())
        .filter(|i| Some(*i) != anchor_idx)
        .collect();
    let signer_witnesses = ctx
        .wallet
        .sign_owned_inputs(&psbt.unsigned_tx, &wallet_input_idxs, &prevouts)
        .await
        .map_err(CpfpError::WalletSigner)?;
    if signer_witnesses.len() != wallet_input_idxs.len() {
        return Err(CpfpError::WalletSigner(SignerError(format!(
            "the wallet answered for {} of {} inputs",
            signer_witnesses.len(),
            wallet_input_idxs.len()
        ))));
    }
    for (idx, signer_witness) in wallet_input_idxs.into_iter().zip(signer_witnesses) {
        let witness = match signer_witness {
            Some(witness) => witness,
            None => {
                let sighash = key_path_sighash(&psbt.unsigned_tx, idx, &prevouts)
                    .map_err(CpfpError::MalformedChild)?;
                let sig = (ctx.wallet_input_signer)(Message::from(sighash))
                    .await
                    .map_err(CpfpError::WalletSigner)?;
                let mut witness = Witness::new();
                witness.push(sig.as_ref());
                witness
            }
        };
        psbt.inputs[idx].final_script_witness = Some(witness);
    }

    // `max_fee_rate` is the only limit on what a child pays. A child holds the fee of the whole
    // package in its own few vbytes, so a per-transaction limit refuses a package under the cap.
    psbt.extract_tx_with_fee_rate_limit(FeeRate::MAX)
        .map_err(|e| CpfpError::MalformedChild(format!("{e:?}")))
}

/// The output that each input of `psbt` spends, in input order.
///
/// A missing `witness_utxo` is an error and not a panic: `psbt` crosses the [`CpfpWallet`]
/// boundary, a failed bump retries, and a panic ends the bump task with no follow-up, so a carried
/// job gets no answer.
fn prevouts_of(psbt: &Psbt) -> Result<Vec<TxOut>, String> {
    psbt.inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| format!("PSBT input {i}: witness_utxo not populated"))
        })
        .collect()
}

/// Computes the BIP-341 **script-path** sighash for one input of a child.
///
/// Differs from [`key_path_sighash`] in that the message commits to the specific leaf being
/// satisfied (via its [`TapLeafHash`]), so a signature made for one leaf cannot be replayed
/// against another. Used for multi-anchor outputs, whose leaves are
/// `<watchtower_pubkey> OP_CHECKSIG`.
fn script_path_sighash(
    tx: &Transaction,
    input_idx: usize,
    prevouts: &[TxOut],
    leaf_script: &ScriptBuf,
) -> Result<bitcoin::TapSighash, String> {
    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
    SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            input_idx,
            &Prevouts::All(prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| format!("script-path sighash compute (input {input_idx}): {e:?}"))
}

/// Computes the BIP-341 key-path Taproot sighash for one input of a child.
///
/// Uses [`TapSighashType::Default`] (sighash byte omitted from the witness; signature is the
/// bare 64-byte Schnorr signature).
fn key_path_sighash(
    tx: &Transaction,
    input_idx: usize,
    prevouts: &[TxOut],
) -> Result<bitcoin::TapSighash, String> {
    SighashCache::new(tx)
        .taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map_err(|e| format!("sighash compute (input {input_idx}): {e:?}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bitcoin::{
        Address, Network, OutPoint, TxIn, XOnlyPublicKey, absolute,
        hashes::Hash,
        opcodes, script,
        secp256k1::{Keypair, SECP256K1},
        taproot::{LeafVersion, TaprootBuilder},
        transaction::Version,
    };
    use bitcoind_async_client::error::ClientError;
    use btc_tracker::cpfp::{DeadlineClass, FirstBump};
    use operator_wallet::test_utils::empty_lease;
    use proptest::prelude::*;
    use strata_bridge_primitives::cpfp::ChildSpend;

    use super::*;

    // ── Test doubles ─────────────────────────────────────────────────────────

    #[derive(Debug)]
    struct FakeFeeSource {
        rate: Mutex<Result<FeeRate, FeeSourceError>>,
    }
    impl FakeFeeSource {
        fn returning(rate: FeeRate) -> Self {
            Self {
                rate: Mutex::new(Ok(rate)),
            }
        }
        fn failing() -> Self {
            Self {
                rate: Mutex::new(Err(FeeSourceError::NoEstimate)),
            }
        }
    }
    #[async_trait]
    impl FeeSource for FakeFeeSource {
        async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
            self.rate.lock().unwrap().clone()
        }
    }

    /// A lease that appends its outpoints to a shared log when it drops.
    ///
    /// The tests read that log to make sure that each path which stops the bumps returns the
    /// funding inputs of the last child. A production lease returns them to the wallet. This
    /// one records the same event.
    #[derive(Debug)]
    struct FakeLease {
        inputs: Vec<FundingInput>,
        lease: Lease,
        released: Arc<Mutex<Vec<OutPoint>>>,
    }
    impl FundingLease for FakeLease {
        fn inputs(&self) -> &[FundingInput] {
            &self.inputs
        }

        fn lease(&self) -> &Lease {
            &self.lease
        }
    }
    impl Drop for FakeLease {
        fn drop(&mut self) {
            self.released
                .lock()
                .unwrap()
                .extend(self.inputs.iter().map(|input| input.outpoint));
        }
    }

    /// What the ladder passed to one build.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RecordedBuild {
        target: FeeRate,
        inputs: Vec<OutPoint>,
        incumbent: Option<IncumbentChild>,
    }

    #[derive(Debug)]
    struct FakeWallet {
        psbt_template: Mutex<Option<Psbt>>,
        spent_template: Vec<OutPoint>,
        error: Option<CpfpWalletError>,
        /// Every build the ladder asked for, in call order.
        builds: Mutex<Vec<RecordedBuild>>,
        /// Outpoints of every lease that has dropped, in drop order.
        released: Arc<Mutex<Vec<OutPoint>>>,
        /// The witness that the signer returns for each input it signs. Empty means that the
        /// signer holds no key.
        signer_witnesses: Vec<(usize, Witness)>,
        /// Inputs that the ladder asked the signer to sign, per call.
        sign_requests: Mutex<Vec<Vec<usize>>>,
        /// Error that the wallet signer reports, when set.
        sign_error: Option<SignerError>,
        /// Whether the inputs of a child read as this wallet's own.
        owns_children: bool,
        /// Whether the signer answers for one input too few.
        drops_a_signature: bool,
        /// How many refreshes the ladder asked for.
        refreshes: Mutex<usize>,
    }
    impl FakeWallet {
        fn with(psbt: Option<Psbt>, spent: Vec<OutPoint>, error: Option<CpfpWalletError>) -> Self {
            Self {
                psbt_template: Mutex::new(psbt),
                spent_template: spent,
                error,
                builds: Mutex::new(Vec::new()),
                released: Arc::new(Mutex::new(Vec::new())),
                signer_witnesses: Vec::new(),
                sign_requests: Mutex::new(Vec::new()),
                sign_error: None,
                owns_children: false,
                drops_a_signature: false,
                refreshes: Mutex::new(0),
            }
        }
        fn returning(psbt: Psbt, spent: Vec<OutPoint>) -> Self {
            Self::with(Some(psbt), spent, None)
        }
        fn failing(msg: &str) -> Self {
            Self::with(
                None,
                Vec::new(),
                Some(CpfpWalletError::Transient(msg.to_string())),
            )
        }

        /// A wallet that reports a parent which can never carry a child.
        fn unbumpable(msg: &str) -> Self {
            Self::with(
                None,
                Vec::new(),
                Some(CpfpWalletError::Unbumpable(msg.to_string())),
            )
        }

        /// A wallet that refuses a replacement above the cap.
        fn above_cap() -> Self {
            Self::with(
                None,
                Vec::new(),
                Some(CpfpWalletError::AboveCap {
                    needed: Amount::from_sat(2),
                    ceiling: Amount::from_sat(1),
                }),
            )
        }

        /// The package rate of the last build.
        fn target(&self) -> Option<FeeRate> {
            self.last_build().map(|build| build.target)
        }

        /// What the ladder passed to the last build.
        fn last_build(&self) -> Option<RecordedBuild> {
            self.builds.lock().unwrap().last().cloned()
        }

        /// Builds a lease over `outpoints` that reports its own drop to this wallet.
        fn lease(&self, outpoints: Vec<OutPoint>) -> Arc<dyn FundingLease> {
            Arc::new(FakeLease {
                inputs: outpoints
                    .into_iter()
                    .map(|outpoint| FundingInput {
                        outpoint,
                        txout: TxOut::NULL,
                    })
                    .collect(),
                lease: empty_lease(),
                released: Arc::clone(&self.released),
            })
        }
    }
    #[async_trait]
    impl CpfpWallet for FakeWallet {
        async fn build_cpfp_child(
            &self,
            _parent: &Transaction,
            _strategy: &CpfpStrategy,
            target_pkg_fee_rate: FeeRate,
            _max_package_rate: FeeRate,
            replaced: ReplacedChild<'_>,
        ) -> Result<WalletFundedPsbt, CpfpWalletError> {
            self.builds.lock().unwrap().push(RecordedBuild {
                target: target_pkg_fee_rate,
                inputs: replaced
                    .prior
                    .iter()
                    .flat_map(|child| child.inputs)
                    .map(|i| i.outpoint)
                    .collect(),
                incumbent: replaced.incumbent,
            });
            if let Some(e) = &self.error {
                return Err(match e {
                    CpfpWalletError::Unbumpable(m) => CpfpWalletError::Unbumpable(m.clone()),
                    CpfpWalletError::AboveCap { needed, ceiling } => CpfpWalletError::AboveCap {
                        needed: *needed,
                        ceiling: *ceiling,
                    },
                    CpfpWalletError::Transient(m) => CpfpWalletError::Transient(m.clone()),
                });
            }
            let psbt = self.psbt_template.lock().unwrap().clone();
            Ok(WalletFundedPsbt {
                psbt: psbt.expect("test must seed a psbt template"),
                lease: self.lease(self.spent_template.clone()),
            })
        }

        async fn adopt_child(
            &self,
            _parent: Txid,
            inputs: Vec<FundingInput>,
        ) -> Option<Arc<dyn FundingLease>> {
            self.owns_children
                .then(|| self.lease(inputs.into_iter().map(|i| i.outpoint).collect()))
        }

        async fn refresh(&self) -> Result<(), CpfpWalletError> {
            *self.refreshes.lock().unwrap() += 1;
            Ok(())
        }

        async fn sign_owned_inputs(
            &self,
            _tx: &Transaction,
            input_indices: &[usize],
            _prevouts: &[TxOut],
        ) -> Result<Vec<Option<Witness>>, SignerError> {
            self.sign_requests
                .lock()
                .unwrap()
                .push(input_indices.to_vec());
            if let Some(e) = &self.sign_error {
                return Err(e.clone());
            }
            let answered = input_indices.len() - usize::from(self.drops_a_signature);
            Ok(input_indices[..answered]
                .iter()
                .map(|index| {
                    self.signer_witnesses
                        .iter()
                        .find(|(signed, _)| signed == index)
                        .map(|(_, witness)| witness.clone())
                })
                .collect())
        }
    }

    /// How a [`FakeMempool`] answers a submission.
    #[derive(Debug, Clone)]
    enum SubmitResult {
        Accepted,
        Rejected(String),
        /// The RPC call failed, so the result is unknown.
        Unknown,
    }

    #[derive(Debug)]
    struct FakeMempool {
        result: Mutex<SubmitResult>,
        /// Per-tx error strings attached to a rejection.
        tx_errors: Mutex<Vec<(Txid, String)>>,
        captured: Mutex<Vec<Vec<Transaction>>>,
        parent_probe: Mutex<ParentProbe>,
        /// Error the probe reports, when set.
        probe_error: Mutex<Option<String>>,
        /// Whether a lookup of the inputs of a child fails.
        inputs_fail: bool,
        /// The answer of [`CpfpMempool::min_fee_rate`]. `None` fails the call.
        min_fee_rate: Option<FeeRate>,
        /// How often the ladder read the minimum.
        min_fee_reads: Mutex<u32>,
    }
    impl FakeMempool {
        fn with_result(result: SubmitResult) -> Self {
            Self {
                result: Mutex::new(result),
                tx_errors: Mutex::new(Vec::new()),
                captured: Mutex::new(Vec::new()),
                parent_probe: Mutex::new(ParentProbe::NoChild),
                probe_error: Mutex::new(None),
                inputs_fail: false,
                min_fee_rate: Some(FeeRate::ZERO),
                min_fee_reads: Mutex::new(0),
            }
        }
        fn ok() -> Self {
            Self::with_result(SubmitResult::Accepted)
        }
        fn failing(reason: &str) -> Self {
            Self::with_result(SubmitResult::Rejected(reason.to_string()))
        }
        fn with_probe(self, probe: ParentProbe) -> Self {
            *self.parent_probe.lock().unwrap() = probe;
            self
        }
        /// Sets what later probes report.
        fn report(&self, probe: ParentProbe) {
            *self.parent_probe.lock().unwrap() = probe;
        }
        /// Makes the probe fail, so a test exercises the build-on-probe-error path.
        fn with_failing_probe(self, reason: &str) -> Self {
            *self.probe_error.lock().unwrap() = Some(reason.to_string());
            self
        }
        /// How many packages reached this fake.
        fn submissions(&self) -> usize {
            self.captured.lock().unwrap().len()
        }
        /// Attaches a per-tx error string to the rejection that this fake reports.
        fn with_tx_error(self, txid: Txid, err: &str) -> Self {
            self.tx_errors.lock().unwrap().push((txid, err.to_string()));
            self
        }
    }
    #[async_trait]
    impl CpfpMempool for FakeMempool {
        async fn submit_package(
            &self,
            txs: &[Transaction],
        ) -> Result<SubmitPackageSummary, SubmitPackageError> {
            self.captured.lock().unwrap().push(txs.to_vec());
            match self.result.lock().unwrap().clone() {
                SubmitResult::Accepted => Ok(SubmitPackageSummary {
                    replaced: Vec::new(),
                }),
                SubmitResult::Rejected(message) => Err(SubmitPackageError::Rejected {
                    message,
                    tx_errors: self.tx_errors.lock().unwrap().clone(),
                }),
                SubmitResult::Unknown => Err(SubmitPackageError::Rpc(ClientError::Timeout)),
            }
        }

        /// Reports the configured probe, or the configured probe error. The default is a parent
        /// with no child, so tests exercise the build path.
        async fn probe(&self, _parent: Txid) -> Result<ParentProbe, MempoolError> {
            if let Some(err) = self.probe_error.lock().unwrap().clone() {
                return Err(MempoolError(err));
            }
            Ok(*self.parent_probe.lock().unwrap())
        }

        async fn child_inputs(&self, _child: Txid) -> Result<Vec<FundingInput>, MempoolError> {
            if self.inputs_fail {
                return Err(MempoolError("child lookup failed".to_string()));
            }
            Ok(vec![FundingInput {
                outpoint: OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0),
                txout: TxOut::NULL,
            }])
        }

        async fn min_fee_rate(&self) -> Result<FeeRate, MempoolError> {
            *self.min_fee_reads.lock().unwrap() += 1;
            self.min_fee_rate
                .ok_or_else(|| MempoolError("no minimum".to_string()))
        }
    }

    fn fake_input_signer_ok() -> InputSigner {
        Arc::new(|_msg: Message| {
            Box::pin(async move {
                // Schnorr signature is 64 bytes; bytes don't have to verify for unit tests of
                // the bump-loop control flow.
                let sig = Signature::from_slice(&[7u8; 64]).expect("64 bytes is a valid sig");
                Ok::<_, SignerError>(sig)
            })
        })
    }

    fn fake_input_signer_failing(message: &'static str) -> InputSigner {
        Arc::new(move |_msg: Message| {
            let m = message.to_string();
            Box::pin(async move { Err(SignerError(m)) })
        })
    }

    /// Runs one attempt and reads its result.
    async fn run_bump(
        ctx: &CpfpContext,
        parent: &Transaction,
        strategy: &CpfpStrategy,
        handle: &mut CpfpHandle,
    ) -> Result<BumpOutcome, CpfpError> {
        perform_bump(ctx, parent, strategy, handle).await.outcome()
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
    /// Inputs carry only `witness_utxo`; `perform_bump` is responsible for signing both inputs
    /// via its caller-provided signers.
    fn synthetic_child_psbt(parent: &Transaction, anchor_vout: u32) -> Psbt {
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
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: wallet_script,
        });
        psbt
    }

    /// Build a synthetic child PSBT for an owned spend: parent output + funding input + change.
    /// Both inputs carry only `witness_utxo`; `perform_bump` signs them via
    /// `wallet_input_signer`.
    fn owned_output_child_psbt(
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

    fn context(
        fee_source: Arc<dyn FeeSource>,
        wallet: Arc<dyn CpfpWallet>,
        mempool: Arc<dyn CpfpMempool>,
        anchor_signer: InputSigner,
        wallet_signer: InputSigner,
        max_fee_rate: FeeRate,
    ) -> CpfpContext {
        CpfpContext {
            wallet,
            fee_source,
            multi_anchor_signer: anchor_signer.clone(),
            anchor_input_signer: anchor_signer,
            wallet_input_signer: wallet_signer,
            // Neutral fee settings: the premium and floor stay off, so that the target is the raw
            // estimate. The fee-setting tests build their own context.
            policy: FeeTargetPolicy {
                premium_percent: 0,
                min_package_fee_rate: FeeRate::ZERO,
                max_fee_rate,
            },
            mempool,
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    fn anchor_strategy(parent: &Transaction) -> CpfpStrategy {
        CpfpStrategy {
            spend: ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0)),
            parent_fee: Amount::from_sat(220),
            deadline: DeadlineClass::NoDeadline,
            first_bump: FirstBump::AtPublish,
        }
    }

    /// A minimal one-leaf multi-anchor strategy. The contention tests use this shape to cover the
    /// shared-anchor path.
    /// The leaf and control block stay structurally valid even though the skip paths never
    /// spend the anchor.
    fn multi_anchor_strategy(parent: &Transaction, anchor_key: XOnlyPublicKey) -> CpfpStrategy {
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
        CpfpStrategy {
            spend: ChildSpend::multi_anchor(
                OutPoint::new(parent.compute_txid(), 0),
                leaf,
                control_block,
            ),
            parent_fee: Amount::from_sat(220),
            deadline: DeadlineClass::NoDeadline,
            first_bump: FirstBump::AtPublish,
        }
    }

    fn seeded_handle(wallet: &FakeWallet, inputs: &[OutPoint], our_child: Txid) -> CpfpHandle {
        CpfpHandle {
            accepted: Some(HeldChild {
                txid: our_child,
                lease: wallet.lease(inputs.to_vec()),
            }),
            ..CpfpHandle::default()
        }
    }

    /// A probe that reports a child of 200 vB that pays 500 sat, in a package at `rate`.
    fn child_at(txid: Txid, rate: FeeRate) -> ParentProbe {
        ParentProbe::Child(MempoolChild {
            txid,
            fee: Amount::from_sat(500),
            vbytes: NonZeroU64::new(200).unwrap(),
            pkg_fee_rate: rate,
        })
    }

    /// The incumbent that the wallet must see for a [`child_at`] probe.
    fn incumbent_of_child_at() -> IncumbentChild {
        IncumbentChild {
            fee: Amount::from_sat(500),
            vbytes: NonZeroU64::new(200).unwrap(),
        }
    }

    /// The outpoints that the leases of the handle hold, or an empty vector when it holds none.
    fn held_by(handle: &CpfpHandle) -> Vec<OutPoint> {
        [&handle.accepted, &handle.candidate]
            .into_iter()
            .flatten()
            .flat_map(|child| child.lease.inputs().iter().map(|i| i.outpoint))
            .collect()
    }

    fn contention_context(wallet: Arc<FakeWallet>, mempool: Arc<FakeMempool>) -> CpfpContext {
        context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(8).unwrap(),
            )),
            wallet,
            mempool,
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
        let mempool = Arc::new(
            FakeMempool::failing("skip must not submit")
                .with_probe(child_at(theirs, FeeRate::from_sat_per_vb_unchecked(10))),
        );
        let ctx = contention_context(wallet.clone(), mempool);
        let mut handle = seeded_handle(&wallet, &inputs, ours);
        let bumped = run_bump(
            &ctx,
            &parent,
            &multi_anchor_strategy(&parent, anchor_key),
            &mut handle,
        )
        .await
        .expect("losing the anchor is a skip, not an error");
        assert_eq!(
            bumped,
            BumpOutcome::ParentIsLive,
            "a child that spends the anchor proves the parent reached the network"
        );
        assert_eq!(*wallet.released.lock().unwrap(), inputs.to_vec());
        assert!(handle.accepted.is_none() && handle.candidate.is_none());
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
        let mempool = Arc::new(
            FakeMempool::failing("skip must not submit")
                .with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(10))),
        );
        let ctx = contention_context(wallet.clone(), mempool);
        let mut handle = seeded_handle(&wallet, &inputs, ours);
        let bumped = run_bump(
            &ctx,
            &parent,
            &multi_anchor_strategy(&parent, anchor_key),
            &mut handle,
        )
        .await
        .expect("holding the anchor is a skip, not an error");
        assert_eq!(
            bumped,
            BumpOutcome::ParentIsLive,
            "a child that spends the anchor proves the parent reached the network"
        );
        assert!(wallet.released.lock().unwrap().is_empty());
        assert_eq!(held_by(&handle), inputs.to_vec());
    }

    /// A failed probe does not stop a first child: the submission is the authority.
    #[tokio::test]
    async fn a_failed_probe_builds_when_the_handle_records_no_child() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![OutPoint {
                txid: parent.compute_txid(),
                vout: 7,
            }],
        ));
        let mempool = Arc::new(FakeMempool::ok().with_failing_probe("probe RPC failure"));
        let ctx = contention_context(wallet.clone(), mempool.clone());
        let mut handle = CpfpHandle::default();
        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("a probe failure must not fail the bump");
        assert_eq!(bumped, BumpOutcome::Submitted);
        assert_eq!(
            mempool.captured.lock().unwrap().len(),
            1,
            "the build must reach the submission despite the probe error"
        );
    }

    #[tokio::test]
    async fn happy_path_submits_package_and_updates_handle() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0);
        let wallet_funding = vec![OutPoint {
            txid: bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
            vout: 0,
        }];

        let mempool = Arc::new(FakeMempool::ok());
        let wallet = Arc::new(FakeWallet::returning(psbt, wallet_funding.clone()));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            mempool.clone(),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(50).unwrap(),
        );

        let mut handle = CpfpHandle::default();
        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("happy path must submit");
        assert_eq!(bumped, BumpOutcome::Submitted);

        // handle is updated
        assert_eq!(wallet.target(), Some(FeeRate::from_sat_per_vb(10).unwrap()));
        assert_eq!(held_by(&handle), wallet_funding);
        assert!(handle.accepted.is_some());

        // mempool received [parent, child]
        let captured = mempool.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].len(), 2);
        assert_eq!(captured[0][0].compute_txid(), parent.compute_txid());
    }

    /// A rejected candidate is not the incumbent, and the node did not relay it: the handle
    /// records nothing and the inputs go back to the wallet.
    #[tokio::test]
    async fn a_rejected_candidate_is_not_recorded() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0);
        let wallet_funding = vec![OutPoint {
            txid: bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
            vout: 0,
        }];

        let mempool = Arc::new(FakeMempool::failing("min relay fee not met"));
        let wallet = Arc::new(FakeWallet::returning(psbt, wallet_funding.clone()));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            mempool.clone(),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(50).unwrap(),
        );

        let mut handle = CpfpHandle::default();
        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect_err("a failing mempool must surface the error");

        assert!(handle.accepted.is_none() && handle.candidate.is_none());
        assert_eq!(*wallet.released.lock().unwrap(), wallet_funding);
    }

    /// The mempool read needs no price. A fee outage still adopts a live child of ours, and the
    /// fresh read still reports the parent.
    #[tokio::test]
    async fn a_fee_source_failure_still_adopts_a_live_child() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ours = Txid::from_byte_array([0xAA; 32]);
        let ctx = context(
            Arc::new(FakeFeeSource::failing()),
            Arc::new(FakeWallet {
                owns_children: true,
                ..FakeWallet::failing("no build")
            }),
            Arc::new(FakeMempool::ok().with_probe(child_at(ours, FeeRate::ZERO))),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut state = BumpState::default();

        let outcome = ctx
            .bump(&parent, &anchor_strategy(&parent), &mut state)
            .await;

        assert_eq!(outcome, BumpOutcome::ParentIsLive);
        let handle = state
            .get::<CpfpHandle>()
            .expect("the bump stores its handle");
        assert_eq!(handle.accepted_txid(), Some(ours));
    }

    /// An attempt that read no parent reports no parent, whatever an earlier attempt read.
    #[tokio::test]
    async fn a_fee_source_failure_after_an_eviction_does_not_report_a_live_parent() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let mempool = Arc::new(FakeMempool::ok().with_probe(ParentProbe::NoChild));
        let ctx = context(
            Arc::new(FakeFeeSource::failing()),
            Arc::new(FakeWallet::failing("no build")),
            mempool.clone(),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut state = BumpState::default();
        let strategy = anchor_strategy(&parent);

        assert_eq!(
            ctx.bump(&parent, &strategy, &mut state).await,
            BumpOutcome::ParentIsLive
        );
        mempool.report(ParentProbe::Absent);
        assert_eq!(
            ctx.bump(&parent, &strategy, &mut state).await,
            BumpOutcome::NoPackage
        );
    }

    #[tokio::test]
    async fn fee_source_failure_surfaces() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ctx = context(
            Arc::new(FakeFeeSource::failing()),
            Arc::new(FakeWallet::failing("wallet must not be called")),
            Arc::new(FakeMempool::failing("mempool must not be called")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let err = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();
        assert!(matches!(err, CpfpError::FeeSource(_)));
        assert!(handle.accepted.is_none());
    }

    #[tokio::test]
    async fn anchor_signer_failure_surfaces() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0);

        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            Arc::new(FakeMempool::failing("must not be called when signer fails")),
            fake_input_signer_failing("anchor sign boom"),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let err = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();
        assert!(matches!(err, CpfpError::AnchorSigner(_)));
        assert!(handle.accepted.is_none());
    }

    /// A funding failure can hide a top-up, so the next attempt must read a fresh view.
    #[tokio::test]
    async fn a_funding_failure_refreshes_the_wallet() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let wallet = Arc::new(FakeWallet::failing("insufficient funds"));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            Arc::new(FakeMempool::failing("must not be called")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        perform_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .outcome()
            .unwrap_err();
        assert_eq!(*wallet.refreshes.lock().unwrap(), 1);
    }

    /// A parent that cannot carry a child does not depend on the view of the wallet.
    #[tokio::test]
    async fn an_unbumpable_parent_does_not_refresh_the_wallet() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let wallet = Arc::new(FakeWallet::unbumpable("no such output"));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            Arc::new(FakeMempool::failing("must not be called")),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        perform_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .outcome()
            .unwrap_err();
        assert_eq!(*wallet.refreshes.lock().unwrap(), 0);
    }

    /// The child spends an input that the chain already spent. The handle must forget the child,
    /// or the next build re-admits that input, and the view must catch up with the chain.
    #[tokio::test]
    async fn a_missing_input_clears_the_handle_and_refreshes_the_wallet() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0);
        let stale = OutPoint::new(Txid::from_byte_array([8; 32]), 0);
        let wallet = Arc::new(FakeWallet::returning(psbt, vec![stale]));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            Arc::new(FakeMempool::failing(
                "package-not-child-with-unconfirmed-parents",
            )),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let mut handle = seeded_handle(&wallet, &[stale], Txid::from_byte_array([7; 32]));
        perform_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .outcome()
            .unwrap_err();
        assert!(handle.accepted.is_none());
        assert!(handle.candidate.is_none());
        assert_eq!(*wallet.refreshes.lock().unwrap(), 1);
    }

    /// A witness that the signer returns is final. The ladder must not sign that input
    /// again: its own signer holds another key.
    #[tokio::test]
    async fn a_signer_witness_is_used_verbatim() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0);
        let sentinel = Signature::from_slice(&[0x42u8; 64]).expect("64 bytes");
        let mut sentinel_witness = Witness::new();
        sentinel_witness.push(sentinel.as_ref());

        let panicking_wallet_signer: InputSigner = Arc::new(|_msg: Message| {
            Box::pin(async move { panic!("the signer signed every wallet input") })
        });

        let wallet = FakeWallet {
            signer_witnesses: vec![(1, sentinel_witness.clone())],
            ..FakeWallet::returning(psbt, Vec::new())
        };
        let wallet = Arc::new(wallet);
        let mempool = Arc::new(FakeMempool::ok());
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            mempool.clone(),
            fake_input_signer_ok(),
            panicking_wallet_signer,
            FeeRate::from_sat_per_vb(50).unwrap(),
        );
        let mut handle = CpfpHandle::default();
        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("the bump must submit without the wallet input signer");
        assert_eq!(bumped, BumpOutcome::Submitted);

        assert_eq!(
            *wallet.sign_requests.lock().unwrap(),
            vec![vec![1]],
            "the anchor is not a wallet input"
        );
        let captured = mempool.captured.lock().unwrap();
        assert_eq!(captured[0][1].input[1].witness, sentinel_witness);
    }

    #[tokio::test]
    async fn an_owned_spend_submits_without_the_anchor_signer() {
        // An owned spend has no foreign-key input. The bump must:
        // (a) build the child via the wallet,
        // (b) NOT invoke the anchor signer,
        // (c) submit the package as usual.
        //
        // We assert (b) by supplying an anchor signer that panics if called — the test would
        // panic instead of pass if the bump incorrectly entered the anchor path.
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
        // The "parent" is a dummy v3 tx — its content doesn't matter for an owned spend,
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
        let psbt = owned_output_child_psbt(payout_outpoint, wallet_script);

        let panicking_anchor_signer: InputSigner = Arc::new(|_msg: Message| {
            Box::pin(async move {
                panic!("anchor signer must NOT be called for an owned spend");
            })
        });

        let mempool = Arc::new(FakeMempool::ok());
        let wallet = Arc::new(FakeWallet::returning(psbt, vec![payout_outpoint]));
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            mempool.clone(),
            panicking_anchor_signer,
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(50).unwrap(),
        );

        let mut handle = CpfpHandle::default();
        let strategy = CpfpStrategy {
            spend: ChildSpend::owned_output(payout_outpoint),
            parent_fee: Amount::from_sat(300),
            deadline: DeadlineClass::NoDeadline,
            first_bump: FirstBump::AtPublish,
        };
        let bumped = run_bump(&ctx, &parent, &strategy, &mut handle)
            .await
            .expect("an owned spend must submit");
        assert_eq!(bumped, BumpOutcome::Submitted);

        assert_eq!(wallet.target(), Some(FeeRate::from_sat_per_vb(10).unwrap()));
        assert!(handle.accepted.is_some());

        // mempool received [parent, child]
        let captured = mempool.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].len(), 2);
        assert_eq!(captured[0][0].compute_txid(), parent.compute_txid());
    }

    /// A rejection means that the node did not take the child and did not relay it. The new
    /// lease drops, and the lease of the live child stays, even with no input in common.
    #[tokio::test]
    async fn a_rejected_replacement_keeps_the_lease_of_the_live_child() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![outpoint(7)],
        ));
        let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            Arc::new(
                FakeMempool::failing("package-not-valid")
                    .with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
            ),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();

        assert_eq!(*wallet.released.lock().unwrap(), vec![outpoint(7)]);
        assert_eq!(held_by(&handle), vec![outpoint(8)]);
        assert_eq!(handle.accepted_txid(), Some(ours));
    }

    /// An RPC failure does not prove that the package stayed off the network. The candidate
    /// keeps its lease, and a later probe that reports the child promotes it. The child is ours,
    /// so its funding stays held and no lookup runs.
    #[tokio::test]
    async fn a_submission_with_an_unknown_result_keeps_the_child_of_a_later_probe() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let funding = vec![OutPoint::new(parent.compute_txid(), 7)];
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            funding.clone(),
        ));
        let mempool = Arc::new(FakeMempool::with_result(SubmitResult::Unknown));
        let ctx = contention_context(wallet.clone(), mempool.clone());
        let mut handle = CpfpHandle::default();
        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();
        let child_txid = handle.candidate.as_ref().expect("the lease stays").txid;
        assert!(handle.accepted.is_none());

        mempool.report(child_at(child_txid, FeeRate::from_sat_per_vb(8).unwrap()));
        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("the live child ends the attempt");

        assert_eq!(bumped, BumpOutcome::ParentIsLive);
        assert_eq!(handle.accepted_txid(), Some(child_txid));
        assert!(wallet.released.lock().unwrap().is_empty());
        assert_eq!(held_by(&handle), funding);
    }

    /// An unknown submission result leaves the live child and its lease in place.
    #[tokio::test]
    async fn a_failed_bump_stores_both_leases() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![outpoint(7)],
        ));
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(
                FakeMempool::with_result(SubmitResult::Unknown)
                    .with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(1))),
            ),
        );
        let mut state = BumpState::new(seeded_handle(&wallet, &[outpoint(8)], ours));

        let outcome = ctx
            .bump(&parent, &anchor_strategy(&parent), &mut state)
            .await;

        assert_ne!(outcome, BumpOutcome::Submitted);
        let handle = state
            .get::<CpfpHandle>()
            .expect("the bump stores its handle");
        assert_eq!(held_by(handle), vec![outpoint(8), outpoint(7)]);
    }

    /// A failed signature means that nothing reached the network. The new lease drops, which
    /// returns its inputs, and the lease of the prior child stays: that child is still live.
    #[tokio::test]
    async fn a_failed_signature_drops_the_new_lease_and_keeps_the_prior_one() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let outpoint = |vout| OutPoint {
            txid: parent.compute_txid(),
            vout,
        };
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![outpoint(7)],
        ));
        let mut handle = seeded_handle(&wallet, &[outpoint(8)], Txid::all_zeros());
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            wallet.clone(),
            Arc::new(FakeMempool::ok().with_probe(child_at(
                Txid::all_zeros(),
                FeeRate::from_sat_per_vb_unchecked(5),
            ))),
            fake_input_signer_ok(),
            fake_input_signer_failing("signer offline"),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();

        assert_eq!(*wallet.released.lock().unwrap(), vec![outpoint(7)]);
        assert_eq!(held_by(&handle), vec![outpoint(8)]);
    }

    /// A wallet signing failure is a retry, never a stop.
    #[tokio::test]
    async fn a_wallet_signing_failure_retries_on_the_next_trigger() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let wallet = FakeWallet {
            sign_error: Some(SignerError("vault offline".to_string())),
            ..FakeWallet::returning(synthetic_child_psbt(&parent, 0), Vec::new())
        };
        let mempool = Arc::new(FakeMempool::ok().with_probe(ParentProbe::Absent));
        let ctx = contention_context(Arc::new(wallet), mempool.clone());

        let outcome = ctx
            .bump(
                &parent,
                &anchor_strategy(&parent),
                &mut BumpState::default(),
            )
            .await;

        assert_eq!(outcome, BumpOutcome::NoPackage);
        assert_eq!(mempool.submissions(), 0);
    }

    /// A child holds the fee of the whole package in its own few vbytes. No limit on its own rate
    /// stops a package that the cap allows.
    #[tokio::test]
    async fn a_child_with_a_very_high_own_rate_reaches_the_node() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let mut psbt = synthetic_child_psbt(&parent, 0);
        psbt.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_btc(1.0).unwrap();
        let mempool = Arc::new(FakeMempool::ok());
        let ctx = contention_context(
            Arc::new(FakeWallet::returning(psbt, Vec::new())),
            mempool.clone(),
        );

        let bumped = run_bump(
            &ctx,
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await
        .expect("the package must submit");

        assert_eq!(bumped, BumpOutcome::Submitted);
        assert_eq!(mempool.submissions(), 1);
    }

    /// A signer that answers for fewer inputs than it was asked about must not reach the
    /// network: a missing witness is a signer fault, and the next trigger retries.
    #[tokio::test]
    async fn a_signer_that_drops_a_signature_fails_as_a_signer_fault() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let wallet = FakeWallet {
            drops_a_signature: true,
            ..FakeWallet::returning(synthetic_child_psbt(&parent, 0), Vec::new())
        };
        let mempool = Arc::new(FakeMempool::ok());
        let ctx = contention_context(Arc::new(wallet), mempool.clone());

        let err = run_bump(
            &ctx,
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, CpfpError::WalletSigner(_)), "got {err:?}");
        assert_eq!(mempool.submissions(), 0);
    }

    fn held(wallet: &FakeWallet, seed: u8) -> HeldChild {
        HeldChild {
            txid: Txid::from_byte_array([seed; 32]),
            lease: wallet.lease(vec![OutPoint::new(Txid::from_byte_array([seed; 32]), 0)]),
        }
    }

    /// Every submission result over a handle with both slots set. `A` is accepted, `B` is the
    /// candidate, and `C` is the new child.
    #[test]
    fn a_submission_result_moves_the_leases_of_the_handle() {
        let rejection = SubmitPackageError::Rejected {
            message: "package-not-valid".to_string(),
            tx_errors: Vec::new(),
        };
        let contention = SubmitPackageError::Rejected {
            message: "transaction failed".to_string(),
            tx_errors: vec![(Txid::all_zeros(), "rejecting replacement".to_string())],
        };
        let unknown = SubmitPackageError::Rpc(ClientError::Timeout);
        let (a, b, c) = (0xA, 0xB, 0xC);

        for (result, accepted, candidate) in [
            (Ok(()), c, None),
            (Err(&unknown), a, Some(c)),
            (Err(&rejection), a, None),
            (Err(&contention), a, None),
        ] {
            let wallet = FakeWallet::failing("no build");
            let mut handle = CpfpHandle {
                accepted: Some(held(&wallet, a)),
                candidate: Some(held(&wallet, b)),
            };
            handle.record_submission(held(&wallet, c), result);

            assert_eq!(
                handle.accepted_txid(),
                Some(Txid::from_byte_array([accepted; 32]))
            );
            assert_eq!(
                handle.candidate.as_ref().map(|child| child.txid),
                candidate.map(|seed| Txid::from_byte_array([seed; 32]))
            );
        }
    }

    /// A probe that reads the candidate makes it the accepted child, and the lease of the older
    /// accepted child drops.
    #[test]
    fn a_probe_that_reads_the_candidate_promotes_it() {
        let wallet = FakeWallet::failing("no build");
        let (a, b) = (held(&wallet, 0xA), held(&wallet, 0xB));
        let (first, second) = (a.txid, b.txid);
        let mut handle = CpfpHandle {
            accepted: Some(a),
            candidate: Some(b),
        };

        assert_eq!(handle.observe(Some(&child_at(second, FeeRate::ZERO))), None);

        assert_eq!(handle.accepted_txid(), Some(second));
        assert!(handle.candidate.is_none());
        assert_eq!(
            *wallet.released.lock().unwrap(),
            vec![OutPoint::new(first, 0)]
        );
    }

    /// A child with no fee must not reach a signer or the network.
    #[tokio::test]
    async fn a_child_with_no_readable_fee_fails_before_signing() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let mut psbt = synthetic_child_psbt(&parent, 0);
        psbt.inputs[1].witness_utxo = None;
        let wallet = Arc::new(FakeWallet::returning(psbt, Vec::new()));
        let mempool = Arc::new(FakeMempool::ok());
        let ctx = contention_context(wallet.clone(), mempool.clone());

        let err = run_bump(
            &ctx,
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, CpfpError::MalformedChild(_)), "got {err:?}");
        assert!(wallet.sign_requests.lock().unwrap().is_empty());
        assert_eq!(mempool.submissions(), 0);
    }

    /// An accepted replacement frees the inputs of the child it replaced.
    #[tokio::test]
    async fn an_accepted_replacement_takes_over_from_the_live_child() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![outpoint(7)],
        ));
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(
                FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
            ),
        );
        let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("the replacement must submit");

        assert_eq!(bumped, BumpOutcome::Submitted);
        assert_eq!(*wallet.released.lock().unwrap(), vec![outpoint(8)]);
        assert_eq!(held_by(&handle), vec![outpoint(7)]);
        assert_ne!(handle.accepted_txid(), Some(ours));
    }

    /// A live child under the target hands its size, its fee, the cap and its inputs to the
    /// build, whoever built it.
    #[tokio::test]
    async fn a_child_of_ours_below_the_target_is_outbid_with_its_own_inputs() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![outpoint(7)],
        ));
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(
                FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
            ),
        );
        let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("the replacement must submit");

        assert_eq!(
            wallet.last_build(),
            Some(RecordedBuild {
                target: FeeRate::from_sat_per_vb(8).unwrap(),
                inputs: vec![outpoint(8)],
                incumbent: Some(incumbent_of_child_at()),
            })
        );
    }

    /// A foreign child below the target sets the price of the build. The inputs of our beaten
    /// child stay available to that build, and no lookup makes the foreign child ours.
    #[tokio::test]
    async fn a_foreign_child_below_the_target_is_outbid() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
        let ours = Txid::from_byte_array([0xAA; 32]);
        let theirs = Txid::from_byte_array([0xBB; 32]);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![outpoint(7)],
        ));
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(
                FakeMempool::ok()
                    .with_probe(child_at(theirs, FeeRate::from_sat_per_vb_unchecked(5))),
            ),
        );
        let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

        let bumped = run_bump(
            &ctx,
            &parent,
            &multi_anchor_strategy(&parent, anchor_key),
            &mut handle,
        )
        .await
        .expect("the outbid must submit");

        assert_eq!(bumped, BumpOutcome::Submitted);
        let build = wallet.last_build().expect("the ladder must build");
        assert_eq!(build.inputs, vec![outpoint(8)]);
        assert_eq!(build.incumbent, Some(incumbent_of_child_at()));
    }

    /// A replacement above the cap is refused. Nothing is signed or submitted, the live child
    /// keeps its lease, and the parent counts as live.
    #[tokio::test]
    async fn a_replacement_above_the_cap_leaves_the_live_child_in_place() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let inputs = [OutPoint::new(parent.compute_txid(), 8)];
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet::above_cap());
        let mempool = Arc::new(
            FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
        );
        let ctx = contention_context(wallet.clone(), mempool.clone());
        let mut handle = seeded_handle(&wallet, &inputs, ours);

        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("a refusal is not an error");

        assert_eq!(bumped, BumpOutcome::ParentIsLive);
        assert_eq!(mempool.submissions(), 0);
        assert!(wallet.released.lock().unwrap().is_empty());
        assert_eq!(held_by(&handle), inputs.to_vec());
    }

    /// A foreign child that the cap keeps this operator from outbidding ends the attempt, so the
    /// inputs of our beaten child go back to the wallet.
    #[tokio::test]
    async fn a_refused_outbid_of_a_foreign_child_frees_the_beaten_child() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let inputs = [OutPoint::new(parent.compute_txid(), 8)];
        let wallet = Arc::new(FakeWallet::above_cap());
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(FakeMempool::ok().with_probe(child_at(
                Txid::from_byte_array([0xBB; 32]),
                FeeRate::from_sat_per_vb_unchecked(5),
            ))),
        );
        let mut handle = seeded_handle(&wallet, &inputs, Txid::from_byte_array([0xAA; 32]));

        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("a refusal is not an error");

        assert_eq!(bumped, BumpOutcome::ParentIsLive);
        assert_eq!(*wallet.released.lock().unwrap(), inputs.to_vec());
    }

    /// With no live child, nothing shows that a mempool holds the parent, so a refusal at the cap
    /// must not read as proof of life.
    #[tokio::test]
    async fn a_refusal_with_no_live_child_does_not_report_a_live_parent() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let mempool = Arc::new(FakeMempool::ok().with_probe(ParentProbe::Absent));
        let ctx = contention_context(Arc::new(FakeWallet::above_cap()), mempool.clone());

        let outcome = ctx
            .bump(
                &parent,
                &anchor_strategy(&parent),
                &mut BumpState::default(),
            )
            .await;

        assert_eq!(outcome, BumpOutcome::NoPackage);
        assert_eq!(mempool.submissions(), 0);
    }

    /// A candidate on a spent output would come back through the replaced inputs and fail the
    /// same way on every trigger. A plain rejection clears the slot, so the next build selects
    /// from what the wallet lists.
    #[tokio::test]
    async fn a_plain_rejection_clears_a_stale_candidate() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let stale = OutPoint::new(parent.compute_txid(), 8);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            Vec::new(),
        ));
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(FakeMempool::failing("package-not-valid")),
        );
        let mut handle = seeded_handle(&wallet, &[stale], Txid::from_byte_array([0xAA; 32]));

        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();
        assert_eq!(wallet.last_build().unwrap().inputs, vec![stale]);
        assert!(held_by(&handle).is_empty());

        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();
        assert_eq!(wallet.last_build().unwrap().inputs, Vec::new());
    }

    /// One slot holds the candidate. A newer child with an unknown result takes it over, and the
    /// lease of the older one drops.
    #[tokio::test]
    async fn a_newer_child_with_an_unknown_result_takes_over_the_candidate_slot() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let older = OutPoint::new(parent.compute_txid(), 8);
        let newer = OutPoint::new(parent.compute_txid(), 7);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![newer],
        ));
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(FakeMempool::with_result(SubmitResult::Unknown)),
        );
        let mut handle = seeded_handle(&wallet, &[older], Txid::from_byte_array([0xAA; 32]));

        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .unwrap_err();

        assert_eq!(held_by(&handle), vec![newer]);
        assert_eq!(*wallet.released.lock().unwrap(), vec![older]);
    }

    /// With a live child recorded, a failed probe leaves nothing to price against. The build
    /// waits, and the outcome does not claim a parent that no probe read.
    #[tokio::test]
    async fn a_failed_probe_skips_the_build_when_the_handle_records_a_live_child() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let inputs = [OutPoint::new(parent.compute_txid(), 8)];
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet::failing("the build must wait"));
        let mempool = Arc::new(FakeMempool::ok().with_failing_probe("probe RPC failure"));
        let ctx = contention_context(wallet.clone(), mempool.clone());
        let mut handle = seeded_handle(&wallet, &inputs, ours);

        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("a failed probe is not an error");

        assert_eq!(bumped, BumpOutcome::NoPackage);
        assert!(wallet.builds.lock().unwrap().is_empty());
        assert_eq!(held_by(&handle), inputs.to_vec());
    }

    /// A child that left the mempool is not an incumbent. Its inputs stay available, because the
    /// wallet can still hide them.
    #[tokio::test]
    async fn a_build_after_a_child_left_the_mempool_has_no_incumbent() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            vec![outpoint(7)],
        ));
        let ctx = contention_context(wallet.clone(), Arc::new(FakeMempool::ok()));
        let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

        run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("the rebuild must submit");

        let build = wallet.last_build().expect("the ladder must build");
        assert_eq!(build.incumbent, None);
        assert_eq!(build.inputs, vec![outpoint(8)]);
    }

    /// After a restart the handle is empty and our child is in the mempool. The ladder adopts it:
    /// the handle takes its identity and a lease on its wallet inputs, and it stands.
    #[tokio::test]
    async fn an_empty_handle_adopts_our_live_child() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet {
            owns_children: true,
            ..FakeWallet::failing("the live child meets the target")
        });
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(
                FakeMempool::ok()
                    .with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(10))),
            ),
        );
        let mut handle = CpfpHandle::default();

        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("an adopted child ends the attempt");

        assert_eq!(bumped, BumpOutcome::ParentIsLive);
        assert_eq!(handle.accepted_txid(), Some(ours));
        assert_eq!(
            held_by(&handle),
            vec![OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0)]
        );
    }

    /// A small wallet can only fund the replacement of an adopted child from that child's own
    /// inputs, so they reach the same attempt's build.
    #[tokio::test]
    async fn an_adopted_child_below_the_target_passes_its_inputs_to_the_build() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let ours = Txid::from_byte_array([0xAA; 32]);
        let wallet = Arc::new(FakeWallet {
            owns_children: true,
            ..FakeWallet::returning(synthetic_child_psbt(&parent, 0), Vec::new())
        });
        let ctx = contention_context(
            wallet.clone(),
            Arc::new(
                FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
            ),
        );

        run_bump(
            &ctx,
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await
        .expect("the replacement must submit");

        let build = wallet.last_build().expect("the ladder must build");
        assert_eq!(
            build.inputs,
            vec![OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0)]
        );
        assert_eq!(build.incumbent, Some(incumbent_of_child_at()));
    }

    /// With no answer on who owns the live child, nothing is released. The next attempt reads
    /// it again.
    #[tokio::test]
    async fn a_failed_child_lookup_releases_nothing() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let inputs = [OutPoint::new(parent.compute_txid(), 8)];
        let wallet = Arc::new(FakeWallet::failing("the live child meets the target"));
        let mempool = FakeMempool {
            inputs_fail: true,
            ..FakeMempool::ok()
        }
        .with_probe(child_at(
            Txid::from_byte_array([0xBB; 32]),
            FeeRate::from_sat_per_vb_unchecked(10),
        ));
        let ctx = contention_context(wallet.clone(), Arc::new(mempool));
        let mut handle = seeded_handle(&wallet, &inputs, Txid::from_byte_array([0xAA; 32]));

        let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
            .await
            .expect("the live child ends the attempt");

        assert_eq!(bumped, BumpOutcome::ParentIsLive);
        assert!(wallet.released.lock().unwrap().is_empty());
        assert_eq!(held_by(&handle), inputs.to_vec());
    }

    /// The node refuses a package below its minimum when the parent is not in the mempool, so
    /// the minimum lifts the target there, and only there.
    #[tokio::test]
    async fn the_node_minimum_lifts_the_target_only_for_an_absent_parent() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let minimum = FeeRate::from_sat_per_vb(15).unwrap();

        for (probe, expected, reads) in [
            (ParentProbe::Absent, minimum, 1),
            (
                ParentProbe::NoChild,
                FeeRate::from_sat_per_vb(8).unwrap(),
                0,
            ),
        ] {
            let wallet = Arc::new(FakeWallet::returning(
                synthetic_child_psbt(&parent, 0),
                Vec::new(),
            ));
            let mempool = Arc::new(
                FakeMempool {
                    min_fee_rate: Some(minimum),
                    ..FakeMempool::ok()
                }
                .with_probe(probe),
            );
            let ctx = contention_context(wallet.clone(), mempool.clone());

            run_bump(
                &ctx,
                &parent,
                &anchor_strategy(&parent),
                &mut CpfpHandle::default(),
            )
            .await
            .expect("the package must submit");

            assert_eq!(wallet.target(), Some(expected), "probe = {probe:?}");
            assert_eq!(*mempool.min_fee_reads.lock().unwrap(), reads);
        }
    }

    /// A failed read of the minimum does not stop the bump.
    #[tokio::test]
    async fn a_failed_read_of_the_node_minimum_prices_from_the_estimate() {
        let (_, anchor_key) = test_keypair_and_xonly();
        let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            Vec::new(),
        ));
        let mempool = FakeMempool {
            min_fee_rate: None,
            ..FakeMempool::ok()
        }
        .with_probe(ParentProbe::Absent);
        let ctx = contention_context(wallet.clone(), Arc::new(mempool));

        run_bump(
            &ctx,
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await
        .expect("the package must submit");

        assert_eq!(wallet.target(), Some(FeeRate::from_sat_per_vb(8).unwrap()));
    }

    // ── Fee-setting tests (premium + package floor) ─────────────────────────
    //
    // The [`context`] helper pins neutral settings (premium 0, floor 0 = raw estimate), so
    // these tests build their own context and assert the exact target that the ladder hands to
    // the wallet.
    /// A constant-byte signer whose output is recognisable in the final witness, so a test can
    /// prove *which* signer produced a given signature rather than only that signing happened.
    fn fake_input_signer_const(byte: u8) -> InputSigner {
        Arc::new(move |_msg: Message| {
            Box::pin(async move {
                Ok::<_, SignerError>(
                    Signature::from_slice(&[byte; 64]).expect("64 bytes is a valid sig"),
                )
            })
        })
    }

    /// The script-path bump must (a) route the anchor input through the
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

        // Two watchtower-style leaves; ours is leaf 0.
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
        // The synthetic child spends parent:0 (the anchor) + one wallet funding input.
        let psbt = synthetic_child_psbt(&parent, 0);
        let wallet_funding = vec![OutPoint {
            txid: parent.compute_txid(),
            vout: 9,
        }];

        let mempool = Arc::new(FakeMempool::ok());
        let ctx = CpfpContext {
            wallet: Arc::new(FakeWallet::returning(psbt, wallet_funding.clone())),
            fee_source: Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            // Key-path signer must never fire for a script-path anchor: if it does, the bump
            // errors and the assertions below fail loudly.
            anchor_input_signer: fake_input_signer_failing(
                "key-path anchor signer must not be called for a multi-anchor spend",
            ),
            multi_anchor_signer: fake_input_signer_const(0xAA),
            wallet_input_signer: fake_input_signer_const(0xBB),
            // Neutral fee settings: this test pins signer selection, not pricing.
            policy: FeeTargetPolicy {
                premium_percent: 0,
                min_package_fee_rate: FeeRate::ZERO,
                max_fee_rate: FeeRate::from_sat_per_vb(20).unwrap(),
            },
            mempool: mempool.clone(),
        };
        let strategy = CpfpStrategy {
            spend: ChildSpend::multi_anchor(
                OutPoint::new(parent.compute_txid(), 0),
                our_leaf.clone(),
                control_block.clone(),
            ),
            parent_fee: Amount::from_sat(200),
            deadline: DeadlineClass::NoDeadline,
            first_bump: FirstBump::AtPublish,
        };
        let mut handle = CpfpHandle::default();
        let submitted = run_bump(&ctx, &parent, &strategy, &mut handle)
            .await
            .expect("script-path bump must succeed");
        assert_eq!(submitted, BumpOutcome::Submitted);
        assert_eq!(held_by(&handle), wallet_funding);

        let packages = mempool.captured.lock().unwrap();
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

    /// A replacement rejection of the child proves nothing about the parent: the child also spends
    /// wallet inputs, and the rejection can come from any of them. Only the probe shows the
    /// parent. A rejection of the parent itself overrides the probe: a conflict holds its place.
    #[tokio::test]
    async fn a_rejected_child_reports_the_probe_and_a_rejected_parent_does_not() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let parent_txid = parent.compute_txid();
        let child = Txid::from_byte_array([0xEE; 32]);
        let funding = vec![OutPoint {
            txid: parent_txid,
            vout: 7,
        }];
        let marker = "insufficient fee, rejecting replacement";

        for (rejected, probe, expected) in [
            (parent_txid, ParentProbe::Absent, BumpOutcome::NoPackage),
            (parent_txid, ParentProbe::NoChild, BumpOutcome::NoPackage),
            (child, ParentProbe::Absent, BumpOutcome::NoPackage),
            (child, ParentProbe::NoChild, BumpOutcome::ParentIsLive),
        ] {
            let ctx = context(
                Arc::new(FakeFeeSource::returning(
                    FeeRate::from_sat_per_vb(10).unwrap(),
                )),
                Arc::new(FakeWallet::returning(
                    synthetic_child_psbt(&parent, 0),
                    funding.clone(),
                )),
                Arc::new(
                    FakeMempool::failing("package rbf failure")
                        .with_tx_error(rejected, marker)
                        .with_probe(probe),
                ),
                fake_input_signer_ok(),
                fake_input_signer_ok(),
                FeeRate::from_sat_per_vb(20).unwrap(),
            );
            let outcome = ctx
                .bump(
                    &parent,
                    &anchor_strategy(&parent),
                    &mut BumpState::default(),
                )
                .await;
            assert_eq!(
                outcome, expected,
                "rejected = {rejected}, probe = {probe:?}"
            );
        }
    }

    /// A failed attempt on a parent that the probe read in the mempool reports a live parent, so
    /// no duty fails and no bare resubmission runs for it.
    #[tokio::test]
    async fn a_failed_attempt_on_a_parent_in_the_mempool_reports_it_live() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let psbt = synthetic_child_psbt(&parent, 0);
        let no_funds = FakeWallet::failing("no funds now");
        let bad_signer = FakeWallet {
            sign_error: Some(SignerError("vault offline".to_string())),
            ..FakeWallet::returning(psbt.clone(), Vec::new())
        };
        let rejected = FakeWallet::returning(psbt, Vec::new());

        for (wallet, mempool) in [
            (no_funds, FakeMempool::ok()),
            (bad_signer, FakeMempool::ok()),
            (rejected, FakeMempool::failing("package-not-valid")),
        ] {
            let ctx = contention_context(Arc::new(wallet), Arc::new(mempool));
            let outcome = ctx
                .bump(
                    &parent,
                    &anchor_strategy(&parent),
                    &mut BumpState::default(),
                )
                .await;
            assert_eq!(outcome, BumpOutcome::ParentIsLive);
        }
    }

    /// A parent that meets the target reports what the probe read.
    #[tokio::test]
    async fn a_parent_that_needs_no_child_reports_what_the_probe_read() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));
        let strategy = CpfpStrategy {
            parent_fee: Amount::from_sat(1_000_000),
            ..anchor_strategy(&parent)
        };

        for (probe, expected) in [
            (ParentProbe::NoChild, BumpOutcome::ParentIsLive),
            (ParentProbe::Absent, BumpOutcome::NoPackage),
        ] {
            let ctx = contention_context(
                Arc::new(FakeWallet::failing("no build")),
                Arc::new(FakeMempool::ok().with_probe(probe)),
            );
            let outcome = ctx
                .bump(&parent, &strategy, &mut BumpState::default())
                .await;
            assert_eq!(outcome, expected);
        }
    }

    /// A wallet that reports a permanent failure stops the bumps, and a transient failure
    /// leaves the parent to the next trigger.
    #[tokio::test]
    async fn a_permanent_wallet_failure_reads_as_unbumpable() {
        let (_, key) = test_keypair_and_xonly();
        let parent = synthetic_parent(key, Amount::from_sat(330));

        for (wallet, expected) in [
            (
                FakeWallet::unbumpable("anchor vout 9 out of range"),
                BumpOutcome::Unbumpable,
            ),
            (FakeWallet::failing("no funds now"), BumpOutcome::NoPackage),
        ] {
            let ctx = context(
                Arc::new(FakeFeeSource::returning(
                    FeeRate::from_sat_per_vb(10).unwrap(),
                )),
                Arc::new(wallet),
                Arc::new(
                    FakeMempool::failing("mempool must not be called")
                        .with_probe(ParentProbe::Absent),
                ),
                fake_input_signer_ok(),
                fake_input_signer_ok(),
                FeeRate::from_sat_per_vb(20).unwrap(),
            );
            let outcome = ctx
                .bump(
                    &parent,
                    &anchor_strategy(&parent),
                    &mut BumpState::default(),
                )
                .await;
            assert_eq!(outcome, expected);
        }
    }

    fn rate() -> impl Strategy<Value = FeeRate> {
        (0u64..4_000_000).prop_map(FeeRate::from_sat_per_kwu)
    }

    fn probe() -> impl Strategy<Value = Option<ParentProbe>> {
        let child = (0u64..10_000_000, 1u64..1000, rate()).prop_map(|(fee, vbytes, rate)| {
            ParentProbe::Child(MempoolChild {
                txid: Txid::from_byte_array([0xAA; 32]),
                fee: Amount::from_sat(fee),
                vbytes: NonZeroU64::new(vbytes).unwrap(),
                pkg_fee_rate: rate,
            })
        });
        prop_oneof![
            Just(None),
            Just(Some(ParentProbe::Absent)),
            Just(Some(ParentProbe::NoChild)),
            child.prop_map(Some),
        ]
    }

    fn bump_inputs() -> impl Strategy<Value = BumpInputs> {
        (
            (rate(), 0u32..1000, rate(), rate()),
            proptest::option::of(rate()),
            (1u64..100_000, 0u64..10_000_000),
            probe(),
            any::<bool>(),
        )
            .prop_map(
                |(
                    (estimate, premium_percent, min_package_fee_rate, max_fee_rate),
                    node_min,
                    (parent_vbytes, parent_fee),
                    probe,
                    child_unresolved,
                )| BumpInputs {
                    estimate,
                    policy: FeeTargetPolicy {
                        premium_percent,
                        min_package_fee_rate,
                        max_fee_rate,
                    },
                    node_min,
                    parent_vbytes,
                    parent_fee: Amount::from_sat(parent_fee),
                    probe,
                    child_unresolved,
                },
            )
    }

    proptest! {
        #[test]
        fn a_capped_target_sits_at_the_cap(inputs in bump_inputs()) {
            let decision = decide(inputs);
            if decision.wanted > inputs.policy.max_fee_rate {
                prop_assert_eq!(decision.target, inputs.policy.max_fee_rate);
            } else {
                prop_assert_eq!(decision.target, decision.wanted);
            }
        }

        #[test]
        fn the_target_reaches_the_floor_or_the_cap(inputs in bump_inputs()) {
            let policy = inputs.policy;
            prop_assert!(
                decide(inputs).target >= policy.min_package_fee_rate.min(policy.max_fee_rate)
            );
        }

        #[test]
        fn the_node_minimum_counts_only_for_an_absent_parent(inputs in bump_inputs()) {
            let without = BumpInputs { node_min: None, ..inputs };
            if inputs.probe != Some(ParentProbe::Absent) {
                prop_assert_eq!(decide(inputs), decide(without));
            } else {
                prop_assert!(decide(inputs).target >= decide(without).target);
            }
        }

        #[test]
        fn no_build_runs_at_or_above_the_target(inputs in bump_inputs()) {
            let decision = decide(inputs);
            if let (BumpAction::Build { .. }, Some(ParentProbe::Child(child))) =
                (decision.action, inputs.probe)
            {
                prop_assert!(child.pkg_fee_rate < decision.target);
            }
        }

        #[test]
        fn a_build_prices_against_the_live_child(inputs in bump_inputs()) {
            if let BumpAction::Build { incumbent } = decide(inputs).action {
                let live = match inputs.probe {
                    Some(ParentProbe::Child(child)) => Some(child),
                    _ => None,
                };
                prop_assert_eq!(incumbent, live);
            }
        }

        #[test]
        fn a_node_minimum_above_the_cap_never_builds(inputs in bump_inputs()) {
            let inputs = BumpInputs {
                node_min: Some(FeeRate::from_sat_per_kwu(
                    inputs.policy.max_fee_rate.to_sat_per_kwu() + 1,
                )),
                probe: Some(ParentProbe::Absent),
                ..inputs
            };
            let is_build = matches!(decide(inputs).action, BumpAction::Build { .. });
            prop_assert!(!is_build);
        }

        #[test]
        fn a_failed_probe_with_a_recorded_child_never_builds(inputs in bump_inputs()) {
            let inputs = BumpInputs { probe: None, child_unresolved: true, ..inputs };
            let is_build = matches!(decide(inputs).action, BumpAction::Build { .. });
            prop_assert!(!is_build);
        }

    }

    /// A probe that finds nothing moves the live child to the candidate slot.
    #[test]
    fn a_probe_that_finds_no_child_demotes_the_accepted_child() {
        let wallet = FakeWallet::failing("no build");
        for probe in [ParentProbe::Absent, ParentProbe::NoChild] {
            let ours = Txid::from_byte_array([0xAA; 32]);
            let mut handle = seeded_handle(&wallet, &[], ours);
            assert_eq!(handle.observe(Some(&probe)), None);
            assert!(handle.accepted.is_none());
            assert_eq!(handle.candidate.as_ref().map(|c| c.txid), Some(ours));
        }
    }

    /// A failed probe teaches nothing, so the handle stays as it was.
    #[test]
    fn a_failed_probe_leaves_the_handle_as_it_is() {
        let wallet = FakeWallet::failing("no build");
        let ours = Txid::from_byte_array([0xAA; 32]);
        let mut handle = seeded_handle(&wallet, &[], ours);
        assert_eq!(handle.observe(None), None);
        assert_eq!(handle.accepted_txid(), Some(ours));
    }

    /// A spender that neither slot knows comes back for the ownership lookup.
    #[test]
    fn an_unknown_child_returns_for_the_ownership_lookup() {
        let wallet = FakeWallet::failing("no build");
        let theirs = Txid::from_byte_array([0xBB; 32]);
        let mut handle = seeded_handle(&wallet, &[], Txid::from_byte_array([0xAA; 32]));
        let probe = child_at(theirs, FeeRate::ZERO);
        assert_eq!(handle.observe(Some(&probe)), Some(theirs));
    }
}
