//! The [`OperatorWallet`] composer.
//!
//! Composes the general wallet and its signer with the reserved wallet and shared lease
//! bookkeeping. The composer owns:
//!
//! - the descriptor-only general wallet and the [`GeneralSigner`] that custody chose for it,
//! - the descriptor-only reserved wallet (signed downstream by the caller, persisted through a
//!   caller-supplied [`crate::WalletStore`]),
//! - the lease set shared across both wallets,
//! - input selection and transaction construction for the general wallet,
//! - cross-wallet construction helpers that produce PSBTs paying from the general wallet into
//!   reserved-wallet outputs of a caller-specified denomination.
//!
//! Every method that consumes UTXOs returns a [`Lease`] over the outpoints that it consumed.
//! The caller keeps that value for as long as the outpoints must stay held. An error path
//! that drops the value releases the outpoints, so no error path needs an explicit release
//! call. [`Lease::commit`] states when a caller keeps them held past that value.
//!
//! # Selection and signing
//!
//! Selection is synchronous and takes `&mut self`. The caller's exclusive guard makes the read of
//! the held outpoints, the choice, and the lease one step, so two selections cannot pick one
//! outpoint twice, and no other lock is needed for that.
//!
//! Selection returns unsigned PSBTs. The caller takes [`OperatorWallet::general_signer`], releases
//! the wallet, and then signs, so a wait for a signature never sits under a wallet lock. A failed
//! signature drops the lease, which returns the inputs.

use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
    sync::Arc,
    time::Instant,
};

use bdk_wallet::{
    bitcoin::{
        absolute::LockTime, transaction::InputWeightPrediction, Address, Amount, FeeRate, OutPoint,
        Psbt, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey,
    },
    chain::BlockId,
    descriptor,
};
use strata_bridge_primitives::cpfp::{ChildSigner, ChildSpend};
use tokio::time::sleep;
use tracing::error;

use crate::{
    config::OperatorWalletConfig,
    general::{GeneralCustody, GeneralSigner},
    leases::{Lease, LeaseOwner, LeaseSet},
    persist::WalletStore,
    plan::{
        self, ChildPlan, ChildRequest, FundingInput, FundingPlan, FundingRequest, IncumbentChild,
    },
    sync::Backend,
    tracked::{OutputSpend, OutputState, TrackedWallet, UtxoInfo},
    Error,
};

/// A funded PSBT and the lease on the inputs that it spends.
///
/// Both fields are private, and [`Self::into_parts`] is the only way to take the PSBT out.
/// Public fields let a caller write `funded.psbt`, which moves the PSBT and drops the lease in
/// the same expression. The funding inputs of a transaction that the caller is about to sign
/// and broadcast then become selectable again, and a concurrent duty can spend them. The
/// caller must name the lease to reach the PSBT, and so must state what happens to it.
#[derive(Debug)]
#[must_use = "the lease releases the funding inputs as soon as this value drops"]
pub struct LeasedPsbt {
    psbt: Psbt,
    lease: Lease,
}

impl LeasedPsbt {
    /// Splits the value into the funded PSBT and the lease on its inputs.
    ///
    /// The caller keeps the lease for as long as the inputs must stay held. See
    /// [`Lease::commit`].
    pub fn into_parts(self) -> (Psbt, Lease) {
        (self.psbt, self.lease)
    }

    /// The lease on the inputs of this PSBT, for callers that only read it.
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }
}

/// The outcome of one attempt of [`OperatorWallet::sync`], which syncs both wallets.
#[derive(Debug, Clone, Copy)]
pub struct LastSync {
    /// Whether both wallets synced.
    pub succeeded: bool,
    /// When the attempt ended.
    pub at: Instant,
}

/// A child that this wallet built earlier for the same parent.
///
/// A fee bump builds a new child that replaces the earlier ones. The new child may pay with the
/// same wallet outputs as an earlier child, because once it replaces that child those outputs
/// are unspent again.
#[derive(Debug, Clone, Copy)]
pub struct PriorChild<'a> {
    /// Txid of the earlier child. When the mempool shows a wallet output as spent, this tells
    /// whether the spender is this child, so that the output can be reused, or some other
    /// transaction, so that it cannot.
    pub txid: Txid,
    /// The lease that reserves the wallet outputs of the earlier child. The new child may use
    /// those outputs. Outputs that any other lease reserves stay unavailable.
    pub lease: &'a Lease,
    /// The wallet outputs that the earlier child spends, with their values and scripts. The wallet
    /// stops listing them once it sees the earlier child in the mempool, so they are passed here
    /// instead. Without them, a wallet whose only usable output paid for the first child could
    /// never bump its fee.
    pub inputs: &'a [FundingInput],
}

/// What a new child replaces.
///
/// The two fields come from different places, so they can disagree. `prior` comes from the
/// records of this wallet and says which outputs the new child may reuse. `incumbent` comes from
/// the mempool and says which fee the new child must beat. For example, another watchtower's
/// child can have replaced ours, or ours can have dropped out of the mempool.
/// [`ReplacedChild::default`] means that there is nothing to replace.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplacedChild<'a> {
    /// Children that this wallet built earlier for the same parent. The new child replaces them,
    /// because they all spend the same output of the parent.
    pub prior: &'a [PriorChild<'a>],
    /// The child of the parent in the mempool now, whether this wallet or another watchtower
    /// built it. The new child must pay more than it does to replace it. `None` when the mempool
    /// holds no child.
    pub incumbent: Option<IncumbentChild>,
}

/// Which general-wallet UTXOs reserved-wallet funding may select from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralUtxoPolicy {
    /// Exclude unconfirmed general-wallet UTXOs from automatic input selection.
    ConfirmedOnly,
    /// Require more confirmations than the number of blocks defining burial.
    BuriedOnly {
        /// Number of blocks required on top of each input transaction.
        bury_depth: u32,
    },
}

/// The operator's wallet: the general wallet and its signer, composed with the reserved wallet,
/// shared lease bookkeeping, and transaction construction.
#[derive(Debug)]
pub struct OperatorWallet<P> {
    general: TrackedWallet<P>,
    general_signer: GeneralSigner,
    reserved: TrackedWallet<P>,
    config: OperatorWalletConfig,
    leases: Arc<LeaseSet>,
    /// The outcome of the most recent attempt of [`Self::sync`].
    last_sync: Option<LastSync>,
}

impl<P: WalletStore> OperatorWallet<P> {
    /// Loads both wallets from their stores, or creates a wallet whose store is empty. Loading
    /// verifies the persisted identity of each wallet.
    ///
    /// `general` chooses the tracked general script and the signer. `sync_backend` feeds both
    /// wallets. A fresh wallet scans from `bootstrap_checkpoint`, so funds received below it stay
    /// invisible. `initial_leases` is the set of outpoints to seed the lease state with, normally
    /// read from durable storage at startup. They enter as one committed lease under
    /// [`LeaseOwner::Rehydrated`], because the duty that took the original lease ran in an earlier
    /// process.
    pub async fn load_or_create(
        general: GeneralCustody<P>,
        reserved_pubkey: XOnlyPublicKey,
        config: OperatorWalletConfig,
        sync_backend: Backend,
        reserved_store: P,
        bootstrap_checkpoint: Option<BlockId>,
        initial_leases: BTreeSet<OutPoint>,
    ) -> Result<Self, Error> {
        let (general_desc, general_signer, general_store) = general.into_parts();
        let general = TrackedWallet::load_or_create(
            general_desc,
            &config,
            sync_backend.clone(),
            general_store,
            bootstrap_checkpoint,
        )
        .await
        .map_err(|e| Error::GeneralInit(Box::new(e)))?;
        let (reserved_desc, ..) =
            descriptor!(tr(reserved_pubkey)).expect("valid tr() descriptor for reserved");
        let reserved = TrackedWallet::load_or_create(
            reserved_desc,
            &config,
            sync_backend,
            reserved_store,
            bootstrap_checkpoint,
        )
        .await
        .map_err(|e| Error::ReservedInit(Box::new(e)))?;
        Ok(Self {
            general,
            general_signer,
            reserved,
            config,
            leases: Arc::new(LeaseSet::with_committed(initial_leases)),
            last_sync: None,
        })
    }

    /// The general wallet: its script and its chain view. It receives change, CPFP drains, and
    /// payouts at that script.
    pub const fn general(&self) -> &TrackedWallet<P> {
        &self.general
    }

    /// The signer of the general wallet. The value is a handle with no borrow of the wallet, so a
    /// caller signs with no wallet lock held.
    pub fn general_signer(&self) -> GeneralSigner {
        self.general_signer.clone()
    }

    // ── Script accessors ────────────────────────────────────────────────────

    /// Returns the BOSD descriptor where bridge payouts to this operator should be directed.
    ///
    /// It wraps the general wallet's own script, so payouts land on ordinary wallet UTXOs that
    /// the signer can spend and CPFP-bump. This is the assignee's own choice in the cooperative
    /// payout flow: peers honour whatever descriptor is broadcast, so it need not match other
    /// operators' custody.
    ///
    /// Returns a BOSD descriptor for the general wallet's current receive script.
    pub fn descriptor(&self) -> Result<bitcoin_bosd::Descriptor, Error> {
        let address = Address::from_script(&self.general_script_pubkey(), self.config.network)?;
        bitcoin_bosd::Descriptor::try_from(address).map_err(Error::Descriptor)
    }

    /// Returns the general wallet's receive script.
    pub fn general_script_pubkey(&self) -> ScriptBuf {
        self.general.script_pubkey()
    }

    /// Returns the reserved wallet's receive script.
    pub fn reserved_script_pubkey(&self) -> ScriptBuf {
        self.reserved.script_pubkey()
    }

    // ── Lease bookkeeping ───────────────────────────────────────────────────

    /// Returns a snapshot of the outpoints that a lease holds.
    pub fn leased_outpoints(&self) -> BTreeSet<OutPoint> {
        self.leases.held()
    }

    /// Holds `outpoints` under `owner` with no live [`Lease`] value behind them.
    ///
    /// This is for outpoints that durable storage already records and that a duty reads back
    /// and reuses. A caller that still
    /// controls the lifetime of the outpoints takes a normal lease and keeps the value
    /// instead. A sync frees them once their spend is buried.
    pub fn lease_committed(&self, outpoints: Vec<OutPoint>, owner: LeaseOwner) {
        self.leases.take(outpoints, owner).commit();
    }

    // ── Sync status ─────────────────────────────────────────────────────────

    /// Returns the block height of the reserved wallet's local chain tip (its most recent sync
    /// checkpoint).
    ///
    /// This is a non-mutating, in-memory read: it neither contacts the backend nor takes any
    /// internal write path, so health probes can observe sync progress through a shared read
    /// lock without serializing against wallet-dependent duties. The tip covers the reserved
    /// wallet only: the general wallet syncs separately inside [`sync`](Self::sync) and can fail
    /// while this tip advances. [`Self::last_sync`] covers both wallets.
    pub fn local_chain_tip_height(&self) -> u32 {
        self.reserved.tip().height
    }

    /// Returns the block hash of the reserved wallet's local chain tip.
    pub fn reserved_tip_hash(&self) -> bdk_wallet::bitcoin::BlockHash {
        self.reserved.tip().hash
    }

    /// The outcome of the most recent sync attempt of both wallets, or `None` before the first.
    /// Each retry inside [`Self::sync`] is an attempt.
    ///
    /// Each wallet has its own store, so [`Self::local_chain_tip_height`] can advance while the
    /// general wallet fails to sync. This is the signal that covers both. It says nothing about the
    /// signer, which a sync never calls.
    pub const fn last_sync(&self) -> Option<LastSync> {
        self.last_sync
    }

    // ── Reserved-wallet UTXO lookup ─────────────────────────────────────────

    /// Returns every spendable reserved-wallet UTXO whose output value matches `value`. The result
    /// holds unconfirmed and leased outputs too.
    pub fn reserved_utxos_with_value(&self, value: Amount) -> Vec<UtxoInfo> {
        let mut pool = self.reserved.list_utxos();
        pool.retain(|utxo| utxo.amount == value);
        pool
    }

    /// Returns the spendable reserved-wallet UTXO at `outpoint`, whatever its value.
    pub fn reserved_utxo(&self, outpoint: OutPoint) -> Option<UtxoInfo> {
        self.reserved
            .list_utxos()
            .into_iter()
            .find(|utxo| utxo.outpoint == outpoint)
    }

    /// Takes a lease on one free, settled reserved-wallet UTXO of `value`.
    ///
    /// A UTXO is settled once it has more than `bury_depth` confirmations, or immediately when
    /// the transaction that created it spends only general-wallet outputs that have more than
    /// `bury_depth` confirmations: that is this wallet's own refill, composed under
    /// [`GeneralUtxoPolicy::BuriedOnly`]. The answer reads the chain, so a restart does not change
    /// it.
    pub fn reserve_settled(&mut self, value: Amount, bury_depth: u32) -> Option<(OutPoint, Lease)> {
        let held = self.leases.held();
        let selected = self
            .reserved_utxos_with_value(value)
            .into_iter()
            .find(|utxo| {
                !held.contains(&utxo.outpoint)
                    && (utxo.confirmations > bury_depth
                        || self.spends_buried_general_outputs(utxo.outpoint.txid, bury_depth))
            })?;
        let lease = self
            .leases
            .take(vec![selected.outpoint], LeaseOwner::ClaimFunding);
        Some((selected.outpoint, lease))
    }

    /// Whether the reserved wallet holds `txid` and every input of that transaction is a
    /// general-wallet output with more than `bury_depth` confirmations.
    fn spends_buried_general_outputs(&self, txid: Txid, bury_depth: u32) -> bool {
        let Some(tx) = self.reserved.transaction(txid) else {
            return false;
        };
        let inputs: BTreeSet<OutPoint> = tx.input.iter().map(|txin| txin.previous_output).collect();
        let states = self.general.output_states(&inputs);
        inputs.iter().all(|input| {
            states
                .get(input)
                .is_some_and(|state| state.confirmations > bury_depth)
        })
    }

    // ── General-wallet selection ────────────────────────────────────────────

    /// Takes a lease on the first confirmed general-wallet UTXO worth at least `min_value`,
    /// skipping held outpoints. Returns `None` when nothing matches.
    ///
    /// Unlike [`Self::fund_v3_transaction`], this hands back one chosen UTXO for callers that
    /// build a transaction around it, such as one with a fixed non-wallet first input that the
    /// outputs-only funding path cannot express.
    pub fn select_general_utxo(
        &mut self,
        owner: LeaseOwner,
        min_value: Amount,
    ) -> Option<(FundingInput, Lease)> {
        let selected = self
            .confirmed_general_inputs(&self.leases.held())
            .into_iter()
            .find(|input| input.txout.value >= min_value)?;
        let lease = self.leases.take(vec![selected.outpoint], owner);
        Some((selected, lease))
    }

    /// Plans a v3 transaction that pays `outputs` from the general wallet, and returns the
    /// unsigned PSBT with a lease on its inputs. The change output follows `outputs`.
    ///
    /// Selection follows `general_utxo_policy` and skips held outpoints. A caller that stores the
    /// inputs in a durable row selects with [`GeneralUtxoPolicy::BuriedOnly`], so that a reorg no
    /// deeper than `bury_depth` cannot remove an input the row names.
    pub fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        fee_rate: FeeRate,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        let candidates = self.general_candidates(&self.leases.held(), general_utxo_policy)?;
        let change_script = self.general.script_pubkey();
        let request = FundingRequest {
            outputs: &outputs,
            change_script: &change_script,
            fee_rate,
            wallet_input: self.general_signer.input_prediction(),
        };
        let plan = plan::plan_funding(&request, candidates)?;
        Ok(self.lease_funded(plan, outputs, change_script, owner))
    }

    /// Plans a v3 transaction that pays `outputs` from exactly `inputs`, normally a stored
    /// funding plan that a retry replays. Every input must be a spendable output of the general
    /// wallet.
    ///
    /// This path reads no held outpoints and applies no confirmation check, because a
    /// stored plan names outpoints that a committed lease already holds. The caller is
    /// responsible for what it names.
    pub fn fund_v3_transaction_with_inputs(
        &mut self,
        outputs: Vec<TxOut>,
        inputs: &[OutPoint],
        fee_rate: FeeRate,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        let utxos = self.general.list_utxos();
        let inputs = inputs
            .iter()
            .map(|outpoint| {
                utxos
                    .iter()
                    .find(|utxo| utxo.outpoint == *outpoint)
                    .map(FundingInput::from)
                    .ok_or(Error::UnknownInput(*outpoint))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let change_script = self.general.script_pubkey();
        let request = FundingRequest {
            outputs: &outputs,
            change_script: &change_script,
            fee_rate,
            wallet_input: self.general_signer.input_prediction(),
        };
        let plan = plan::plan_explicit_funding(&request, inputs)?;
        Ok(self.lease_funded(plan, outputs, change_script, owner))
    }

    /// Plans a CPFP child for `parent` that spends the output `spend` describes, plus wallet
    /// inputs that cover the child's share of the package fee, and returns the unsigned PSBT.
    ///
    /// `parent_fee` is the caller-known fee already paid by `parent`. Together with the sizes of
    /// the parent and the child, it decides the fee that lifts the package to
    /// `target_pkg_fee_rate`.
    ///
    /// `max_package_rate` is a hard limit: a child that lifts the package past it is not built,
    /// and the error is [`Error::ChildAboveCap`]. A wallet output of the parent that a lease
    /// outside `replaced` holds is not spent either, and the error is
    /// [`Error::ParentOutputHeld`].
    ///
    /// `replaced` describes what this build supersedes through RBF: the live child to outbid and
    /// the prior children of this wallet. The lease of a prior child is untouched: a failed build
    /// leaves it as it was, and the caller drops it once a mempool accepts the new child. An input
    /// of a prior child that a sync shows as spent elsewhere, or that another duty holds, does not
    /// enter this child.
    ///
    /// The returned lease covers the funding inputs, and covers the parent output only when the
    /// general wallet signs for it: once the parent confirms, that output is selectable, and the
    /// lease keeps another duty off it while the child is live. The returned inputs are those the
    /// lease holds, with the outputs they spend. A rebuild passes them back as
    /// [`PriorChild::inputs`], because the wallet stops listing them once a sync observes the
    /// child.
    pub fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        parent_fee: Amount,
        spend: &ChildSpend,
        target_pkg_fee_rate: FeeRate,
        max_package_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<(LeasedPsbt, Vec<FundingInput>), Error> {
        let prior_leases: Vec<&Lease> = replaced.prior.iter().map(|child| child.lease).collect();
        let held_by_others = self.leases.held_excluding(&prior_leases);
        let spent_outpoint = spend.outpoint();
        if spend.signer() == ChildSigner::GeneralWallet && held_by_others.contains(&spent_outpoint)
        {
            return Err(Error::ParentOutputHeld {
                outpoint: spent_outpoint,
            });
        }
        let prior_outpoints = replaced
            .prior
            .iter()
            .flat_map(|child| child.inputs)
            .map(|input| input.outpoint)
            .collect();
        let candidates = with_respendable_inputs(
            self.confirmed_general_inputs(&held_by_others),
            replaced.prior,
            &held_by_others,
            &self.general.output_states(&prior_outpoints),
        );
        let spent = spent_output(parent, spend)?;
        let drain_script = self.general.script_pubkey();
        let wallet_input = self.general_signer.input_prediction();
        let request = ChildRequest {
            // cast: tx vsize is bounded by the 4 MWU consensus limit, far inside u64.
            parent_vbytes: parent.vsize() as u64,
            parent_fee,
            target: target_pkg_fee_rate,
            max_package_rate,
            incumbent: replaced.incumbent,
            spent_value: spent.txout.value,
            spent_input: spent_input_prediction(spend, wallet_input),
            wallet_input,
            drain_script: &drain_script,
        };
        let (psbt, leased_inputs) = plan_child_psbt(&request, spent, spend.signer(), candidates)?;

        let lease = self.leases.take(
            plan::outpoints(&leased_inputs),
            LeaseOwner::CpfpChild {
                parent: spent_outpoint.txid,
            },
        );
        Ok((LeasedPsbt { psbt, lease }, leased_inputs))
    }

    /// Takes a lease on the wallet inputs of a live child of the unconfirmed v3 parent `parent`.
    /// The caller holds no record of that child: a restart or a reorg lost it.
    ///
    /// `inputs` are every input of the child with the output it spends. The wallet keeps those
    /// that pay its own script and returns them with the lease. TRUC limits the spenders of an
    /// unconfirmed v3 parent to one v3 child, so one input of this wallet shows that the child is
    /// this wallet's. A child of another watchtower has none, and the result is `None`.
    pub fn adopt_cpfp_child(
        &self,
        parent: Txid,
        inputs: Vec<FundingInput>,
    ) -> Option<(Lease, Vec<FundingInput>)> {
        let owned = plan::owned_by(inputs, &self.general.script_pubkey());
        if owned.is_empty() {
            return None;
        }
        let lease = self
            .leases
            .take(plan::outpoints(&owned), LeaseOwner::CpfpChild { parent });
        Some((lease, owned))
    }

    // ── Cross-wallet (general → reserved) ──────────────────────────────────

    /// Creates a PSBT that funds `quantity` reserved-wallet UTXOs of `utxo_value` each,
    /// paying from the general wallet. The outputs go to the reserved-wallet script.
    ///
    /// The composer is agnostic of what `utxo_value` means to the caller — it only
    /// enforces that each output carries exactly that value and pays the reserved
    /// script.
    pub fn create_reserved_utxos(
        &mut self,
        fee_rate: FeeRate,
        utxo_value: Amount,
        quantity: usize,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        let outputs: Vec<TxOut> = (0..quantity)
            .map(|_| TxOut {
                value: utxo_value,
                script_pubkey: self.reserved.script_pubkey(),
            })
            .collect();

        let candidates = self.general_candidates(&self.leases.held(), general_utxo_policy)?;

        let change_script = self.general.script_pubkey();
        let request = FundingRequest {
            outputs: &outputs,
            change_script: &change_script,
            fee_rate,
            wallet_input: self.general_signer.input_prediction(),
        };
        let plan = plan::plan_funding(&request, candidates)?;
        Ok(self.lease_funded(plan, outputs, change_script, owner))
    }

    // ── Sync ───────────────────────────────────────────────────────────────

    /// Syncs both wallets against the node, persisting their staged chain state as it goes, and
    /// then drops the leases on outpoints with a buried spend.
    ///
    /// A failure leaves every lease in place. The blocks that the attempt applied stay in the
    /// view; the mempool part of the view stays at the last finished sync. The caller holds the
    /// exclusive guard for this call.
    ///
    /// A spend in the mempool or in an unburied block keeps its lease. A reorg no deeper than
    /// `bury_depth` can undo such a spend, and the outpoint then reads as spendable while a stored
    /// reservation names it. A lease on an outpoint whose spend a reorg removed for good stays
    /// until a restart; the outpoint is a candidate again only through that restart.
    ///
    /// An outpoint that neither wallet knows keeps its lease too. It is the output of a parent
    /// that no block or mempool holds yet, or of a transaction that a conflict removed. Neither
    /// wallet offers such an output for selection, so the lease has no effect until the output
    /// appears, and then it must hold. Such an entry stays for the life of the process, and a
    /// stored record brings it back at startup.
    ///
    /// A spend that a reorg returns to the mempool reads as spent, because the mempool snapshot of
    /// a sync always applies last, against the tip it was read at.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let mut attempt = 0u32;
        loop {
            // Both wallets sync on every attempt, so one store failure does not stop the other
            // wallet from advancing.
            let general_result = self.general.sync().await.map_err(Error::GeneralSync);
            let reserved_result = self.reserved.sync().await.map_err(Error::ReservedSync);
            // Each failure is logged: the result below carries only the first.
            for e in [&general_result, &reserved_result]
                .into_iter()
                .filter_map(|result| result.as_ref().err())
            {
                error!(?e, attempt, "error syncing wallet");
            }
            let result = general_result.and(reserved_result);
            self.last_sync = Some(LastSync {
                succeeded: result.is_ok(),
                at: Instant::now(),
            });
            match result {
                Ok(()) => break,
                Err(e) => {
                    if attempt >= self.config.sync_retries {
                        return Err(e);
                    }
                    sleep(self.config.sync_base_delay * self.config.sync_backoff.pow(attempt))
                        .await;
                    attempt += 1;
                }
            }
        }

        let held = self.leases.held();
        let spent: BTreeSet<OutPoint> = self
            .general
            .output_states(&held)
            .into_iter()
            .chain(self.reserved.output_states(&held))
            .filter(|(_, output)| {
                matches!(
                    output.spend,
                    OutputSpend::Confirmed { confirmations } if confirmations > self.config.bury_depth
                )
            })
            .map(|(outpoint, _)| outpoint)
            .collect();
        self.leases.prune_spent(&spent);
        Ok(())
    }

    /// Returns how many free general-wallet UTXOs a block holds. These are the candidates for a
    /// CPFP funding input. Each one can still be too small for a given fee.
    pub fn free_confirmed_general_utxo_count(&self) -> usize {
        self.confirmed_general_inputs(&self.leases.held()).len()
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    /// The general-wallet outputs outside `held` that `general_utxo_policy` admits. An error
    /// names the outputs that the policy excluded, when nothing else is there.
    fn general_candidates(
        &self,
        held: &BTreeSet<OutPoint>,
        general_utxo_policy: GeneralUtxoPolicy,
    ) -> Result<Vec<FundingInput>, Error> {
        let required_depth = match general_utxo_policy {
            GeneralUtxoPolicy::ConfirmedOnly => 0,
            GeneralUtxoPolicy::BuriedOnly { bury_depth } => bury_depth,
        };
        let (eligible, ineligible): (Vec<UtxoInfo>, Vec<UtxoInfo>) = self
            .general
            .list_utxos()
            .into_iter()
            .filter(|u| !held.contains(&u.outpoint))
            .partition(|u| u.confirmations > required_depth);
        if eligible.is_empty() && !ineligible.is_empty() {
            let unconfirmed_count = ineligible.len();
            let unconfirmed_amount = ineligible
                .iter()
                .fold(Amount::ZERO, |total, u| total + u.amount);
            if let GeneralUtxoPolicy::BuriedOnly { bury_depth } = general_utxo_policy {
                return Err(Error::NoBuriedGeneralUtxos { bury_depth });
            }
            return Err(Error::NoConfirmedGeneralUtxos {
                unconfirmed_count,
                unconfirmed_amount,
            });
        }
        Ok(eligible.iter().map(FundingInput::from).collect())
    }

    /// Returns the general-wallet UTXOs outside `held` that a block holds. The transactions these
    /// fund are v3, and TRUC (BIP-431) rejects a v3 transaction with an unconfirmed non-v3
    /// ancestor, and it caps a v3 transaction with an unconfirmed v3 ancestor to one parent and
    /// one child.
    fn confirmed_general_inputs(&self, held: &BTreeSet<OutPoint>) -> Vec<FundingInput> {
        self.general
            .list_utxos()
            .iter()
            .filter(|utxo| utxo.confirmations > 0 && !held.contains(&utxo.outpoint))
            .map(FundingInput::from)
            .collect()
    }

    /// Takes a lease on the inputs of `plan` and pairs it with the unsigned PSBT.
    fn lease_funded(
        &self,
        plan: FundingPlan,
        mut outputs: Vec<TxOut>,
        change_script: ScriptBuf,
        owner: LeaseOwner,
    ) -> LeasedPsbt {
        let lease = self.leases.take(plan::outpoints(&plan.inputs), owner);
        outputs.extend(plan.change.map(|value| TxOut {
            value,
            script_pubkey: change_script,
        }));
        LeasedPsbt {
            psbt: plan::unsigned_psbt(
                &plan.inputs,
                outputs,
                LockTime::from_height(self.general.tip().height).unwrap_or(LockTime::ZERO),
            ),
            lease,
        }
    }
}

/// Returns `candidates` with the inputs of `prior` that a new child can spend again. `held` holds
/// what other leases hold, and `states` the state of each of those inputs.
fn with_respendable_inputs(
    mut candidates: Vec<FundingInput>,
    prior: &[PriorChild<'_>],
    held: &BTreeSet<OutPoint>,
    states: &BTreeMap<OutPoint, OutputState>,
) -> Vec<FundingInput> {
    let children: Vec<Txid> = prior.iter().map(|child| child.txid).collect();
    for input in prior.iter().flat_map(|child| child.inputs) {
        let listed = candidates.iter().any(|c| c.outpoint == input.outpoint);
        if !listed
            && !held.contains(&input.outpoint)
            && respendable(states.get(&input.outpoint), &children)
        {
            candidates.push(input.clone());
        }
    }
    candidates
}

/// Whether a child that replaces `children` can spend an output in `state`, which the wallet no
/// longer lists.
///
/// Only `children` may spend it, and only from the mempool. Any other spender means that the
/// output is gone, and a child built on it fails at the node on every attempt. An unspent output
/// needs nothing from here, because the wallet lists it and it is a candidate already. Its own
/// transaction must be confirmed: a v3 child has one unconfirmed ancestor, and the parent is that
/// ancestor.
fn respendable(state: Option<&OutputState>, children: &[Txid]) -> bool {
    match state {
        Some(OutputState {
            confirmations: 1..,
            spend: OutputSpend::InMempool(spenders),
        }) => spenders.iter().all(|txid| children.contains(txid)),
        _ => false,
    }
}

/// The parent output that `spend` names, as an input of the child. It comes from `parent` itself,
/// because the parent is usually not broadcast yet. Fails when `spend` names another transaction.
fn spent_output(parent: &Transaction, spend: &ChildSpend) -> Result<FundingInput, Error> {
    let spent_outpoint = spend.outpoint();
    let parent_txid = parent.compute_txid();
    if spent_outpoint.txid != parent_txid {
        return Err(Error::SpendOfAnotherParent {
            spend: spent_outpoint,
            parent: parent_txid,
        });
    }
    let Some(spent_txout) = parent.output.get(spent_outpoint.vout as usize) else {
        return Err(Error::SpendVoutOutOfRange {
            vout: spent_outpoint.vout,
            parent_outputs: parent.output.len(),
        });
    };
    Ok(FundingInput {
        outpoint: spent_outpoint,
        txout: spent_txout.clone(),
    })
}

/// Size of the input that spends the parent output: a wallet input of `wallet_input` size when the
/// general wallet signs for it, and otherwise what the witness of `spend` costs.
fn spent_input_prediction(
    spend: &ChildSpend,
    wallet_input: InputWeightPrediction,
) -> InputWeightPrediction {
    match spend.signer() {
        ChildSigner::GeneralWallet => wallet_input,
        ChildSigner::Protocol => spend.witness().input_prediction(),
    }
}

/// Plans a child for `request` and builds its unsigned PSBT. Returns it with the inputs that a
/// lease must hold: the funding, and `spent` when `signer` is the general wallet.
///
/// `spent` is the parent output that `request` prices. It is input 0 and the wallet inputs
/// follow, so the same request always builds the same transaction. It never joins `candidates`:
/// a confirmed payout that pays the wallet's own script also appears in the wallet.
fn plan_child_psbt(
    request: &ChildRequest<'_>,
    spent: FundingInput,
    signer: ChildSigner,
    mut candidates: Vec<FundingInput>,
) -> Result<(Psbt, Vec<FundingInput>), Error> {
    candidates.retain(|candidate| candidate.outpoint != spent.outpoint);
    let ChildPlan { funding, drain } = plan::plan_child(request, candidates)?;

    let child_inputs: Vec<FundingInput> =
        iter::once(spent).chain(funding.iter().cloned()).collect();
    let drain_output = TxOut {
        value: drain,
        script_pubkey: request.drain_script.to_owned(),
    };
    let psbt = plan::unsigned_psbt(&child_inputs, vec![drain_output], LockTime::ZERO);
    let leased_inputs = match signer {
        ChildSigner::GeneralWallet => child_inputs,
        ChildSigner::Protocol => funding,
    };
    Ok((psbt, leased_inputs))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use bdk_wallet::bitcoin::{
        absolute,
        hashes::Hash,
        opcodes, script,
        secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey},
        taproot::{ControlBlock, LeafVersion, TaprootBuilder},
        transaction::Version,
        Network, TxIn, Txid, Witness,
    };
    use strata_bridge_primitives::cpfp::ChildWitness;

    use super::*;

    const TAPROOT_INPUT: InputWeightPrediction = InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH;
    const P2WPKH_INPUT: InputWeightPrediction = InputWeightPrediction::P2WPKH_MAX;

    fn xonly(seed: u8) -> XOnlyPublicKey {
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid scalar");
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
            .x_only_public_key()
            .0
    }

    /// The Taproot script of a general wallet.
    fn wallet_script() -> ScriptBuf {
        ScriptBuf::new_p2tr(&Secp256k1::new(), xonly(50), None)
    }

    /// The P2WPKH script of a vault.
    fn vault_script() -> ScriptBuf {
        let secret = SecretKey::from_slice(&[51; 32]).expect("valid scalar");
        let key = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        Address::p2wpkh(
            &bdk_wallet::bitcoin::CompressedPublicKey(key),
            Network::Regtest,
        )
        .script_pubkey()
    }

    /// A confirmed wallet output of `sats`, unique per `seed`.
    fn funding(sats: u64, seed: u8) -> FundingInput {
        FundingInput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            txout: TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: wallet_script(),
            },
        }
    }

    /// A v3 parent whose only output pays `script_pubkey`.
    fn parent_with_script_pubkey(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
        parent_with_outputs(vec![TxOut {
            value,
            script_pubkey,
        }])
    }

    fn parent_with_outputs(output: Vec<TxOut>) -> Transaction {
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
            output,
        }
    }

    /// A parent whose output `anchor_vout` is a keyed-Taproot anchor of `anchor_value`, after
    /// dummy outputs, so it looks like a bridge tx with an anchor at a known position.
    fn parent_with_anchor(anchor_vout: u32, anchor_value: Amount) -> Transaction {
        let anchor_script = ScriptBuf::new_p2tr(&Secp256k1::new(), xonly(3), None);
        let mut outputs: Vec<TxOut> = (0..anchor_vout)
            .map(|_| TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: anchor_script.clone(),
            })
            .collect();
        outputs.push(TxOut {
            value: anchor_value,
            script_pubkey: anchor_script,
        });
        parent_with_outputs(outputs)
    }

    /// A `MultiAnchor`-shaped Taproot output: one `<pubkey> OP_CHECKSIG` leaf per watchtower over
    /// a balanced tree. Returns the first leaf and its control block plus the output script.
    fn script_path_anchor(n_watchtowers: usize) -> (ScriptBuf, ControlBlock, ScriptBuf) {
        let secp = Secp256k1::new();
        let leaves: Vec<ScriptBuf> = (0..n_watchtowers)
            .map(|i| {
                script::Builder::new()
                    .push_slice(xonly(i as u8 + 2).serialize())
                    .push_opcode(opcodes::all::OP_CHECKSIG)
                    .into_script()
            })
            .collect();
        let builder =
            TaprootBuilder::with_huffman_tree(leaves.iter().map(|s| (1u32, s.clone()))).unwrap();
        let spend_info = builder.finalize(&secp, xonly(99)).unwrap();
        let control_block = spend_info
            .control_block(&(leaves[0].clone(), LeafVersion::TapScript))
            .unwrap();
        let spk = ScriptBuf::new_p2tr(&secp, xonly(99), spend_info.merkle_root());
        (leaves[0].clone(), control_block, spk)
    }

    /// Measures what `tx` will weigh once signed, by attaching witnesses of the real shape and
    /// letting rust-bitcoin serialize it. This is the independent oracle for the size prediction:
    /// it shares no arithmetic with the planner.
    fn signed_vsize_of(tx: &Transaction, spend: &ChildSpend) -> u64 {
        let mut signed = tx.clone();
        for input in &mut signed.input {
            let mut witness = Witness::new();
            match spend.witness() {
                ChildWitness::ScriptPath {
                    leaf_script,
                    control_block,
                } if input.previous_output == spend.outpoint() => {
                    witness.push([0u8; 64]);
                    witness.push(leaf_script.as_bytes());
                    witness.push(control_block.serialize());
                }
                // Key-path spend and every Taproot wallet input: a bare 64-byte signature.
                _ => witness.push([0u8; 64]),
            }
            input.witness = witness;
        }
        signed.vsize() as u64
    }

    /// Builds a child on a Taproot wallet.
    fn build(
        parent: &Transaction,
        parent_fee: u64,
        spend: &ChildSpend,
        target_sat_vb: u64,
        incumbent: Option<IncumbentChild>,
        candidates: Vec<FundingInput>,
    ) -> Result<Psbt, Error> {
        built(
            parent,
            parent_fee,
            spend,
            target_sat_vb,
            incumbent,
            candidates,
        )
        .map(|(psbt, _)| psbt)
    }

    /// Builds a child on a Taproot wallet, and returns what a lease must hold too.
    fn built(
        parent: &Transaction,
        parent_fee: u64,
        spend: &ChildSpend,
        target_sat_vb: u64,
        incumbent: Option<IncumbentChild>,
        candidates: Vec<FundingInput>,
    ) -> Result<(Psbt, Vec<FundingInput>), Error> {
        let spent = spent_output(parent, spend)?;
        let drain_script = wallet_script();
        let request = ChildRequest {
            parent_vbytes: parent.vsize() as u64,
            parent_fee: Amount::from_sat(parent_fee),
            target: FeeRate::from_sat_per_vb(target_sat_vb).unwrap(),
            max_package_rate: FeeRate::from_sat_per_vb(1000).unwrap(),
            incumbent,
            spent_value: spent.txout.value,
            spent_input: spent_input_prediction(spend, TAPROOT_INPUT),
            wallet_input: TAPROOT_INPUT,
            drain_script: &drain_script,
        };
        plan_child_psbt(&request, spent, spend.signer(), candidates)
    }

    fn funding_of(psbt: &Psbt, spend: &ChildSpend) -> Vec<OutPoint> {
        psbt.unsigned_tx
            .input
            .iter()
            .map(|input| input.previous_output)
            .filter(|outpoint| *outpoint != spend.outpoint())
            .collect()
    }

    /// A replacement child pays the replaced fee plus 1 sat/vB over its own size. At an unchanged
    /// target the rate-based fee equals the prior fee, which BIP-125 rule 4 rejects.
    #[test]
    fn a_replacement_child_pays_the_rbf_floor() {
        let parent = parent_with_anchor(0, Amount::from_sat(330));
        let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0));
        let wallet = vec![funding(1_000_000, 1)];

        let first =
            build(&parent, 220, &spend, 5, None, wallet.clone()).expect("first child must build");
        let first_fee = first.fee().expect("witness_utxo on every input");
        let vbytes = signed_vsize_of(&first.unsigned_tx, &spend);

        let replacement = build(
            &parent,
            220,
            &spend,
            5,
            Some(IncumbentChild {
                fee: first_fee,
                vbytes: NonZeroU64::new(vbytes).unwrap(),
            }),
            wallet,
        )
        .expect("replacement must build");
        assert_eq!(
            replacement.fee().expect("witness_utxo on every input"),
            first_fee + Amount::from_sat(vbytes),
            "replacement fee must sit exactly on the BIP-125 floor"
        );
    }

    fn in_mempool(spenders: &[Txid], confirmations: u32) -> OutputState {
        OutputState {
            confirmations,
            spend: OutputSpend::InMempool(spenders.to_vec()),
        }
    }

    fn txid(seed: u8) -> Txid {
        Txid::from_byte_array([seed; 32])
    }

    /// Once a sync observes the prior child, the wallet stops listing its funding. The rebuild
    /// re-spends it, which is plain RBF because both children spend the same anchor.
    #[test]
    fn an_input_that_a_prior_child_alone_spends_is_respendable() {
        assert!(
            respendable(Some(&in_mempool(&[txid(1)], 3)), &[txid(1)]),
            "an input that only its prior child spends is respendable"
        );
        assert!(
            respendable(
                Some(&in_mempool(&[txid(1), txid(2)], 3)),
                &[txid(1), txid(2)]
            ),
            "an input that only prior children spend is respendable"
        );
    }

    #[test]
    fn an_input_that_another_transaction_spends_is_not_respendable() {
        assert!(
            !respendable(Some(&in_mempool(&[txid(2)], 3)), &[txid(1)]),
            "an input that a foreign transaction spends is not respendable"
        );
        assert!(
            !respendable(Some(&in_mempool(&[txid(1), txid(2)], 3)), &[txid(1)]),
            "a foreign spender next to the prior child keeps the input out"
        );
    }

    /// A rebuild built on this input fails at the node on every attempt. A stored input of a prior
    /// child reads like this once a selection from a stale view picked a spent output.
    #[test]
    fn an_input_with_a_confirmed_spend_is_not_respendable() {
        let state = OutputState {
            confirmations: 3,
            spend: OutputSpend::Confirmed { confirmations: 1 },
        };
        assert!(
            !respendable(Some(&state), &[txid(1)]),
            "a confirmed spend ends the input"
        );
    }

    /// An unspent output is a candidate already, or another duty holds it.
    #[test]
    fn an_unspent_input_does_not_reenter_here() {
        let state = OutputState {
            confirmations: 3,
            spend: OutputSpend::Unspent,
        };
        assert!(
            !respendable(Some(&state), &[txid(1)]),
            "an unspent input is not respendable through this path"
        );
    }

    /// A reorg took the funding of the input out of its block. A v3 child has one unconfirmed
    /// ancestor, and the parent is that ancestor.
    #[test]
    fn an_input_that_no_block_holds_is_not_respendable() {
        assert!(
            !respendable(Some(&in_mempool(&[txid(1)], 0)), &[txid(1)]),
            "an input whose funding no block holds is not respendable"
        );
    }

    #[test]
    fn an_output_that_the_wallet_does_not_know_is_not_respendable() {
        assert!(
            !respendable(None, &[txid(1)]),
            "an output the wallet does not know is not respendable"
        );
    }

    /// A prior child with one input, and the state that says only that child spends it.
    fn spent_by_prior(input: &FundingInput) -> (Txid, BTreeMap<OutPoint, OutputState>) {
        let child = txid(9);
        let states = BTreeMap::from([(input.outpoint, in_mempool(&[child], 3))]);
        (child, states)
    }

    #[test]
    fn a_rebuild_adds_the_input_that_its_prior_child_spends() {
        let input = funding(1_000_000, 1);
        let (txid, states) = spent_by_prior(&input);
        let lease = crate::test_utils::empty_lease();
        let inputs = [input.clone()];
        let prior = [PriorChild {
            txid,
            lease: &lease,
            inputs: &inputs,
        }];
        let listed = funding(5_000, 2);
        let candidates =
            with_respendable_inputs(vec![listed.clone()], &prior, &BTreeSet::new(), &states);
        assert_eq!(
            candidates,
            vec![listed, input],
            "the rebuild adds the input of its prior child after the listed ones"
        );
    }

    /// A second duty took the input after a reorg undid the spend that pruned the prior lease. A
    /// child on it would double-spend that duty.
    #[test]
    fn a_rebuild_leaves_an_input_that_another_lease_holds() {
        let input = funding(1_000_000, 1);
        let (txid, states) = spent_by_prior(&input);
        let lease = crate::test_utils::empty_lease();
        let inputs = [input.clone()];
        let prior = [PriorChild {
            txid,
            lease: &lease,
            inputs: &inputs,
        }];
        let held = BTreeSet::from([input.outpoint]);
        assert!(
            with_respendable_inputs(Vec::new(), &prior, &held, &states).is_empty(),
            "an input that another lease holds does not enter the rebuild"
        );
    }

    /// The wallet still lists the input until a sync observes the prior child. It must enter the
    /// child once.
    #[test]
    fn a_rebuild_does_not_add_an_input_that_the_wallet_still_lists() {
        let input = funding(1_000_000, 1);
        let (txid, states) = spent_by_prior(&input);
        let lease = crate::test_utils::empty_lease();
        let inputs = [input.clone()];
        let prior = [PriorChild {
            txid,
            lease: &lease,
            inputs: &inputs,
        }];
        let candidates =
            with_respendable_inputs(vec![input.clone()], &prior, &BTreeSet::new(), &states);
        assert_eq!(
            candidates,
            vec![input],
            "an input the wallet still lists enters the child once"
        );
    }

    /// A confirmed payout that pays the wallet's own script appears in the wallet too. It must
    /// not join the funding, or the child would spend it twice.
    #[test]
    fn the_spent_output_never_joins_the_funding() {
        let parent = parent_with_script_pubkey(wallet_script(), Amount::from_sat(8_000));
        let outpoint = OutPoint::new(parent.compute_txid(), 0);
        let spend = ChildSpend::owned_output(outpoint);
        let listed = FundingInput {
            outpoint,
            txout: parent.output[0].clone(),
        };
        let err = build(&parent, 0, &spend, 50, None, vec![listed])
            .expect_err("the only candidate is the output the child already spends");
        assert!(
            matches!(err, Error::InsufficientFunds { .. }),
            "the spent output never funds its own child"
        );
    }

    /// The payout-combined shape: the spent output is a full-value payout that pays for the child
    /// on its own, at the exact package make-up fee.
    #[test]
    fn a_payout_pays_the_package_fee_without_funding() {
        let parent = parent_with_anchor(0, Amount::from_sat(1_000_000));
        let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0));
        let psbt = build(&parent, 500, &spend, 20, None, vec![funding(1_000_000, 1)])
            .expect("payout-combined child must build");

        assert_eq!(
            psbt.unsigned_tx.input.len(),
            1,
            "the payout pays for the child alone"
        );
        // 111 vB is the canonical 1-in/1-out Taproot key-path spend.
        let child_vb = 111;
        assert_eq!(
            signed_vsize_of(&psbt.unsigned_tx, &spend),
            child_vb,
            "the child has the size of a 1-in/1-out key-path spend"
        );
        let expected = 20 * (parent.vsize() as u64 + child_vb) - 500;
        assert_eq!(
            psbt.fee().unwrap().to_sat(),
            expected,
            "the child pays the package make-up fee"
        );
    }

    /// An output that the general wallet signs for costs a wallet input, whatever the spend
    /// witness says. On a P2WPKH vault that is the signed size of the payout input.
    #[test]
    fn an_output_of_the_wallet_costs_a_wallet_input() {
        let parent = parent_with_script_pubkey(vault_script(), Amount::from_sat(1_000_000));
        let spend = ChildSpend::owned_output(OutPoint::new(parent.compute_txid(), 0));
        let spent = spent_output(&parent, &spend).expect("the payout is an output of the parent");
        let drain_script = vault_script();
        let request = ChildRequest {
            parent_vbytes: parent.vsize() as u64,
            parent_fee: Amount::ZERO,
            target: FeeRate::from_sat_per_vb(20).unwrap(),
            max_package_rate: FeeRate::from_sat_per_vb(1000).unwrap(),
            incumbent: None,
            spent_value: spent.txout.value,
            spent_input: spent_input_prediction(&spend, P2WPKH_INPUT),
            wallet_input: P2WPKH_INPUT,
            drain_script: &drain_script,
        };
        let psbt = plan_child_psbt(&request, spent, spend.signer(), Vec::new())
            .expect("the payout pays for the child")
            .0;

        // 1 P2WPKH input and 1 P2WPKH output, at 73 signature bytes and 33 pubkey bytes.
        let child_vb = 110;
        let expected = 20 * (parent.vsize() as u64 + child_vb);
        assert_eq!(
            psbt.fee().unwrap().to_sat(),
            expected,
            "a wallet output of the parent is priced as a wallet input"
        );
    }

    /// An anchor worth slightly more than the fee must not yield a below-dust drain output.
    /// `InferGeneralPayout` makes this reachable, because it uses a change output as the anchor,
    /// and change values are arbitrary. The sweep covers the region where the shape flips.
    #[test]
    fn an_anchor_near_the_fee_boundary_still_builds() {
        let parent_vb = parent_with_anchor(0, Amount::from_sat(1)).vsize() as u64;
        for target in [2u64, 3, 5, 10, 20] {
            let fee_at = |vb: u64| target * (parent_vb + vb) - 100;
            // Step 29 is coprime with the 330-sat dust threshold, so the sweep cannot alias past
            // a narrow failing band.
            for anchor in (fee_at(111).saturating_sub(400)..=fee_at(169) + 700).step_by(29) {
                let parent = parent_with_anchor(0, Amount::from_sat(anchor));
                let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0));
                let psbt = build(
                    &parent,
                    100,
                    &spend,
                    target,
                    None,
                    vec![funding(1_000_000, 1)],
                )
                .unwrap_or_else(|e| panic!("{target} sat/vB, anchor {anchor}: {e:?}"));
                let drain = &psbt.unsigned_tx.output[0];
                assert!(
                    drain.value >= drain.script_pubkey.minimal_non_dust(),
                    "the drain output stays above dust"
                );
            }
        }
    }

    /// A script-path child is heavier than a key-path one, and the child pays an absolute fee, so
    /// a size prediction blind to the witness underpays every contest and bridge-proof-timeout
    /// bump. The funding is chosen before the fee, so the shape that was priced is the shape that
    /// got built, and the only slack is rounding.
    #[test]
    fn a_script_path_package_meets_the_target_at_every_tree_depth() {
        for n_watchtowers in [2usize, 3, 5, 9, 16] {
            let (leaf_script, control_block, anchor_spk) = script_path_anchor(n_watchtowers);
            let parent = parent_with_script_pubkey(anchor_spk, Amount::from_sat(330));
            let spend = ChildSpend::multi_anchor(
                OutPoint::new(parent.compute_txid(), 0),
                leaf_script,
                control_block,
            );
            let psbt = build(&parent, 500, &spend, 20, None, vec![funding(1_000_000, 1)])
                .unwrap_or_else(|e| panic!("{n_watchtowers} watchtowers: {e:?}"));

            let package_fee = psbt.fee().unwrap().to_sat() + 500;
            let package_vb = parent.vsize() as u64 + signed_vsize_of(&psbt.unsigned_tx, &spend);
            let required = 20 * package_vb;
            assert!(
                (required..=required + 1).contains(&package_fee),
                "{n_watchtowers} watchtowers: package pays {package_fee} sat over {package_vb} vB"
            );
        }
    }

    /// The fee math holds for a child that draws several funding inputs.
    #[test]
    fn multi_input_funding_pays_the_exact_package_fee() {
        let parent = parent_with_anchor(0, Amount::from_sat(330));
        let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0));
        let wallet = (0..8)
            .map(|i| funding(5_000 + u64::from(i) * 137, i))
            .collect();
        let psbt =
            build(&parent, 308, &spend, 50, None, wallet).expect("multi-input child must build");

        assert!(funding_of(&psbt, &spend).len() >= 2, "several inputs drawn");
        let package_fee = psbt.fee().unwrap().to_sat() + 308;
        let package_vb = parent.vsize() as u64 + signed_vsize_of(&psbt.unsigned_tx, &spend);
        let required = 50 * package_vb;
        assert!(
            (required..=required + 1).contains(&package_fee),
            "the package pays the required fee, with at most one sat of rounding"
        );
    }

    #[test]
    fn a_child_spends_the_anchor_first_and_carries_every_prevout() {
        let parent = parent_with_anchor(2, Amount::from_sat(330));
        let anchor = OutPoint::new(parent.compute_txid(), 2);
        let spend = ChildSpend::keyed_anchor(anchor);
        let psbt = build(&parent, 220, &spend, 5, None, vec![funding(1_000_000, 1)])
            .expect("non-zero-vout anchor must work");

        assert_eq!(
            psbt.unsigned_tx.input[0].previous_output, anchor,
            "the anchor is the first input"
        );
        assert_eq!(
            psbt.unsigned_tx.input.len(),
            2,
            "one funding input joins the anchor"
        );
        assert_eq!(
            psbt.unsigned_tx.version,
            Version(3),
            "the child is a v3 transaction"
        );
        assert!(
            psbt.inputs.iter().all(|i| i.witness_utxo.is_some()),
            "every input carries its prevout"
        );
        assert!(
            psbt.inputs.iter().all(|i| i.final_script_witness.is_none()),
            "the child is unsigned"
        );
        assert_eq!(
            psbt.unsigned_tx.output[0].script_pubkey,
            wallet_script(),
            "the drain pays the wallet"
        );
    }

    #[test]
    fn a_lease_holds_the_funding_of_a_child_of_an_anchor() {
        let parent = parent_with_anchor(0, Amount::from_sat(330));
        let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0));
        let wallet = funding(1_000_000, 1);
        let (_, held) =
            built(&parent, 220, &spend, 5, None, vec![wallet.clone()]).expect("child must build");
        assert_eq!(
            held,
            vec![wallet],
            "the lease holds the funding of an anchor child"
        );
    }

    /// A payout belongs to the wallet, so it needs the lease as much as the funding does.
    #[test]
    fn a_lease_holds_the_spent_output_when_the_general_wallet_signs_for_it() {
        let parent = parent_with_script_pubkey(wallet_script(), Amount::from_sat(400));
        let spend = ChildSpend::owned_output(OutPoint::new(parent.compute_txid(), 0));
        let wallet = funding(1_000_000, 1);
        let (_, held) =
            built(&parent, 0, &spend, 5, None, vec![wallet.clone()]).expect("child must build");
        assert_eq!(
            plan::outpoints(&held),
            vec![spend.outpoint(), wallet.outpoint],
            "the lease holds the spent wallet output and the funding"
        );
    }

    #[test]
    fn a_spent_vout_past_the_parent_outputs_is_refused() {
        let parent = parent_with_anchor(0, Amount::from_sat(330));
        let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 5));
        let err = build(&parent, 220, &spend, 10, None, Vec::new()).unwrap_err();
        assert!(
            matches!(err, Error::SpendVoutOutOfRange { vout: 5, .. }),
            "a vout past the parent outputs is refused"
        );
    }

    /// A spend that names another transaction would take the value and script of the parent's
    /// output at its vout, and the child would pay a wrong fee or carry an invalid signature.
    #[test]
    fn a_spend_of_another_transaction_is_refused() {
        let parent = parent_with_anchor(0, Amount::from_sat(330));
        let spend = ChildSpend::keyed_anchor(OutPoint::new(Txid::all_zeros(), 0));
        let err = build(&parent, 220, &spend, 10, None, Vec::new()).unwrap_err();
        assert!(
            matches!(
                err,
                Error::SpendOfAnotherParent { spend: spent, parent: txid }
                    if spent == spend.outpoint() && txid == parent.compute_txid()
            ),
            "a spend of another transaction is refused, got {err:?}"
        );
    }

    /// With no incumbent, the same request gives the same child, whatever order the wallet lists
    /// its outputs in. A retry after a submission with an unknown result then keeps its txid.
    #[test]
    fn a_build_with_no_incumbent_does_not_depend_on_the_listing_order() {
        let parent = parent_with_anchor(0, Amount::from_sat(330));
        let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0));
        let mut wallet: Vec<FundingInput> = (0..6)
            .map(|i| funding(5_030 + u64::from(i) * 91, i))
            .collect();
        let first =
            build(&parent, 308, &spend, 20, None, wallet.clone()).expect("child must build");
        wallet.reverse();
        let second = build(&parent, 308, &spend, 20, None, wallet).expect("child must build");
        assert_eq!(
            first.unsigned_tx.compute_txid(),
            second.unsigned_tx.compute_txid(),
            "the same request builds the same child in any listing order"
        );
    }
}
