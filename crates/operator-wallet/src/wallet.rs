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

use std::{collections::BTreeSet, sync::Arc, time::Instant};

use bdk_wallet::{
    bitcoin::{
        absolute::LockTime, Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, TxOut, Txid,
        XOnlyPublicKey,
    },
    chain::BlockId,
    descriptor,
};
use tokio::time::sleep;
use tracing::{error, warn};

use crate::{
    config::OperatorWalletConfig,
    general::{GeneralCustody, GeneralSigner},
    leases::{Lease, LeaseOwner, LeaseSet},
    persist::WalletStore,
    plan::{self, FundingInput, FundingPlan, FundingRequest},
    sync::Backend,
    tracked::{OutputSpend, TrackedWallet, UtxoInfo},
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

/// The most recent attempt of [`OperatorWallet::sync`].
#[derive(Debug, Clone, Copy)]
pub struct LastSync {
    /// Whether both wallets synced.
    pub succeeded: bool,
    /// When the attempt ended.
    pub at: Instant,
}

/// Which general-wallet UTXOs reserved-wallet funding may select from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralUtxoPolicy {
    /// Allow the general wallet backend to select confirmed or unconfirmed UTXOs.
    IncludeUnconfirmed,
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
    /// The most recent sync attempt. `None` before the first attempt. The two wallets have
    /// separate stores and sync one after the other inside [`Self::sync`], so the reserved tip
    /// advances while a store failure stops the general wallet, and the tip alone cannot show
    /// that.
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
    /// while this tip advances — probe [`Self::last_sync`] for it.
    pub fn local_chain_tip_height(&self) -> u32 {
        self.reserved.tip().height
    }

    /// Returns the block hash of the reserved wallet's local chain tip.
    pub fn reserved_tip_hash(&self) -> bdk_wallet::bitcoin::BlockHash {
        self.reserved.tip().hash
    }

    /// The most recent sync attempt, or `None` before the first.
    ///
    /// The reserved tip ([`Self::local_chain_tip_height`]) keeps advancing while the general
    /// wallet fails, because each wallet has its own store. A health probe that reads only the
    /// tip therefore reports a general wallet whose store has failed as healthy forever.
    ///
    /// A sync does not reach the signer, so this says nothing about it: an outage of the signer
    /// shows up when a duty signs.
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

        // Exclude already-existing reserved UTXOs of the same value from selection so the
        // composer doesn't accidentally spend pool members back to itself.
        let mut held = self.leases.held();
        held.extend(
            self.reserved_utxos_with_value(utxo_value)
                .into_iter()
                .map(|u| u.outpoint),
        );
        let candidates = self.general_candidates(&held, general_utxo_policy)?;

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

    // ── Internal helpers ───────────────────────────────────────────────────

    /// Every spendable general-wallet output that is not held, confirmed or not, apart from an
    /// unconfirmed output of exactly the CPFP anchor value: that is an anchor a future child
    /// spends.
    fn general_inputs(&self, held: &BTreeSet<OutPoint>) -> Vec<FundingInput> {
        self.general
            .list_utxos()
            .iter()
            .filter(|utxo| !held.contains(&utxo.outpoint))
            .filter(|utxo| !(utxo.confirmations == 0 && utxo.amount == self.config.cpfp_value))
            .map(FundingInput::from)
            .collect()
    }

    /// The general-wallet outputs outside `held` that `general_utxo_policy` admits. An error
    /// names the outputs that the policy excluded, when nothing else is there.
    fn general_candidates(
        &self,
        held: &BTreeSet<OutPoint>,
        general_utxo_policy: GeneralUtxoPolicy,
    ) -> Result<Vec<FundingInput>, Error> {
        let required_depth = match general_utxo_policy {
            GeneralUtxoPolicy::IncludeUnconfirmed => return Ok(self.general_inputs(held)),
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
            warn!(
                unconfirmed_count,
                %unconfirmed_amount,
                required_depth,
                "no sufficiently confirmed general-wallet UTXOs available"
            );
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
