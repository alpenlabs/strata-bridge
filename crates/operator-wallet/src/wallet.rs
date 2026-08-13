//! The [`OperatorWallet`] composer.
//!
//! Composes a swappable [`crate::GeneralWallet`] backend with an always-native reserved wallet
//! and shared lease bookkeeping. The composer owns:
//!
//! - the BDK descriptor-only reserved wallet (signed downstream by the caller, persisted through a
//!   caller-supplied [`crate::WalletStore`]),
//! - the lease set shared across both wallets,
//! - anchor exclusion during input selection,
//! - cross-wallet construction helpers that produce PSBTs paying from the general wallet into
//!   reserved-wallet outputs of a caller-specified denomination.
//!
//! Every method that consumes UTXOs returns a [`Lease`] over the outpoints that it consumed.
//! The caller keeps that value for as long as the outpoints must stay held. An error path
//! that drops the value releases the outpoints, so no error path needs an explicit release
//! call. A caller that records the outpoints in durable storage, or that broadcasts the
//! spend, calls [`Lease::commit`] instead.
//!
//! Methods on [`OperatorWallet`] take `&mut self`. Callers serialize via an outer lock when
//! they need a multi-step critical section, such as a database lookup, then funding, then a
//! write.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    sync::Arc,
};

use bdk_wallet::{
    bitcoin::{
        Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Txid,
        XOnlyPublicKey,
    },
    chain::BlockId,
    descriptor, KeychainKind,
};
use bitcoin_bosd::Descriptor;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::{
    config::OperatorWalletConfig,
    general::{
        is_spendable, local_output_to_utxo_info, AnchorInfo, AnchorOwnership, FundedPsbt,
        GeneralWallet, ReplacedChild, UtxoInfo,
    },
    leases::{Lease, LeaseOwner, LeaseSet},
    persist::{ensure_backend_not_behind, load_or_create, PersistedWallet, WalletStore},
    sync::Backend,
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
    /// The caller keeps the lease for as long as the inputs must stay held, and calls
    /// [`Lease::commit`] once durable storage or a broadcast transaction records them.
    pub fn into_parts(self) -> (Psbt, Lease) {
        (self.psbt, self.lease)
    }

    /// The lease on the inputs of this PSBT, for callers that only read it.
    pub const fn lease(&self) -> &Lease {
        &self.lease
    }

    /// The funded PSBT. See the [`GeneralWallet`] signing contract for which inputs the
    /// backend signs, and which inputs the caller must sign downstream.
    pub const fn psbt(&self) -> &Psbt {
        &self.psbt
    }
}

/// Confirmation requirements for general-wallet funding.
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

/// The operator's wallet: a [`GeneralWallet`] backend composed with the always-native reserved
/// wallet, shared lease bookkeeping, and cross-wallet transaction construction helpers.
#[derive(Debug)]
pub struct OperatorWallet<G, P> {
    general: G,
    reserved: PersistedWallet<P>,
    reserved_store: P,
    reserved_sync_backend: Backend,
    reserved_script_pubkey: ScriptBuf,
    config: OperatorWalletConfig,
    leases: Arc<LeaseSet>,
    /// The node's mempool as of the last successful sync, which decides whether an unconfirmed
    /// reserved output is spendable (see [`is_spendable`]). Kept across a failed sync: callers
    /// carry on after one, and an empty set would hide every unconfirmed output.
    reserved_mempool: HashSet<Txid>,
    funding_txids: BTreeMap<Txid, u32>,
}

impl<G: GeneralWallet, P: WalletStore> OperatorWallet<G, P> {
    /// Constructs an [`OperatorWallet`] from a [`GeneralWallet`] backend and a reserved-wallet
    /// pubkey, loading the reserved wallet from `reserved_store` or creating it when the store is
    /// empty (see [`load_or_create`]). `initial_leases` is the set of outpoints to seed the lease
    /// state with, normally read from durable storage at startup. They enter as one committed
    /// lease under [`LeaseOwner::Rehydrated`], because the duty that took the original lease ran
    /// in an earlier process.
    pub async fn load_or_create(
        general: G,
        reserved_pubkey: XOnlyPublicKey,
        config: OperatorWalletConfig,
        reserved_sync_backend: Backend,
        mut reserved_store: P,
        bootstrap_checkpoint: Option<BlockId>,
        initial_leases: BTreeSet<OutPoint>,
    ) -> Result<Self, Error> {
        let (reserved_desc, ..) =
            descriptor!(tr(reserved_pubkey)).expect("valid tr() descriptor for reserved");
        let reserved = load_or_create(
            &mut reserved_store,
            reserved_desc,
            config.network,
            bootstrap_checkpoint,
        )
        .await
        .map_err(|e| Error::ReservedInit(Box::new(e)))?;
        ensure_backend_not_behind(&reserved_sync_backend, &reserved)
            .await
            .map_err(|e| Error::ReservedInit(Box::new(e)))?;
        let reserved_addr = reserved.peek_address(KeychainKind::External, 0).address;
        info!("reserved wallet address: {reserved_addr}");
        Ok(Self {
            general,
            reserved,
            reserved_store,
            reserved_sync_backend,
            reserved_script_pubkey: reserved_addr.script_pubkey(),
            config,
            leases: Arc::new(LeaseSet::with_committed(initial_leases)),
            reserved_mempool: HashSet::new(),
            funding_txids: BTreeMap::new(),
        })
    }

    /// Returns a reference to the underlying [`GeneralWallet`] for callers that need
    /// backend-specific operations the composer doesn't wrap. Use sparingly.
    pub const fn general(&self) -> &G {
        &self.general
    }

    // ── Script accessors ────────────────────────────────────────────────────

    /// Returns the general wallet's receive script.
    pub fn general_script_pubkey(&self) -> ScriptBuf {
        self.general.script_pubkey()
    }

    /// Returns the reserved wallet's receive script.
    pub fn reserved_script_pubkey(&self) -> ScriptBuf {
        self.reserved_script_pubkey.clone()
    }

    /// Returns a BOSD descriptor for the general wallet's current receive script.
    pub fn descriptor(&self) -> Result<Descriptor, Error> {
        let address = Address::from_script(&self.general_script_pubkey(), self.config.network)?;
        Descriptor::try_from(address).map_err(Error::Descriptor)
    }

    // ── Lease bookkeeping ───────────────────────────────────────────────────

    /// Returns a snapshot of the outpoints that a lease holds.
    pub fn leased_outpoints(&self) -> BTreeSet<OutPoint> {
        self.leases.held()
    }

    /// Holds `outpoints` under `owner` with no live [`Lease`] value behind them.
    ///
    /// This is for outpoints that durable storage already records, such as the inputs of a
    /// stake funding reservation that a duty reads back and reuses. A caller that still
    /// controls the lifetime of the outpoints takes a normal lease and keeps the value
    /// instead. [`Self::release_committed`] frees them again.
    pub fn lease_committed(&self, outpoints: Vec<OutPoint>, owner: LeaseOwner) {
        self.leases.take(outpoints, owner).commit();
    }

    /// Releases `outpoints` that a committed lease holds.
    ///
    /// A live [`Lease`] value keeps its outpoints through this call. Only dropping the value
    /// frees those.
    pub fn release_committed(&self, outpoints: &[OutPoint]) {
        self.leases.release_committed(outpoints);
    }

    // ── Sync status ─────────────────────────────────────────────────────────

    /// Returns the block height of the reserved wallet's local chain tip (its most recent sync
    /// checkpoint).
    ///
    /// This is a non-mutating, in-memory read: it neither contacts the backend nor takes any
    /// internal write path, so health probes can observe sync progress through a shared read
    /// lock without serializing against wallet-dependent duties. Both the general and reserved
    /// wallets advance together in [`sync`](Self::sync), so the reserved tip is representative.
    pub fn local_chain_tip_height(&self) -> u32 {
        self.reserved.latest_checkpoint().height()
    }

    /// Returns the block hash of the reserved wallet's local chain tip.
    pub fn reserved_tip_hash(&self) -> bdk_wallet::bitcoin::BlockHash {
        self.reserved.latest_checkpoint().hash()
    }

    // ── Reserved-wallet UTXO lookup ─────────────────────────────────────────

    /// Returns every reserved-wallet UTXO whose output value matches `value`.
    ///
    /// Used to look up the pool of equal-denomination reserved-wallet UTXOs maintained for
    /// some downstream purpose (claim funding, etc.) — the composer doesn't know what the
    /// caller's "purpose" is, only that they want UTXOs of a specific size.
    pub fn reserved_utxos_with_value(&self, value: Amount) -> Vec<UtxoInfo> {
        let tip = self.reserved.latest_checkpoint().height();
        self.reserved
            .list_unspent()
            .filter(|output| is_spendable(output, &self.reserved_mempool))
            .filter(|utxo| utxo.txout.value == value)
            .map(|lo| local_output_to_utxo_info(&lo, tip))
            .collect()
    }

    /// Returns the spendable reserved-wallet UTXO at `outpoint`, whatever its value.
    pub fn reserved_utxo(&self, outpoint: OutPoint) -> Option<UtxoInfo> {
        let tip = self.reserved.latest_checkpoint().height();
        self.reserved
            .get_utxo(outpoint)
            .filter(|output| is_spendable(output, &self.reserved_mempool))
            .map(|lo| local_output_to_utxo_info(&lo, tip))
    }

    /// Takes a lease on one free reserved-wallet UTXO of value `value` that the `ignore`
    /// predicate does not reject.
    ///
    /// Returns the selected UTXO with its lease, and the number of other matching free UTXOs
    /// left after the selection.
    pub fn reserve_utxo_with_value(
        &self,
        value: Amount,
        owner: LeaseOwner,
        ignore: impl Fn(&UtxoInfo) -> bool,
    ) -> (Option<(OutPoint, Lease)>, u64) {
        let available = self.reserved_utxos_with_value(value);
        let leased = self.leases.held();
        let mut considered = available
            .into_iter()
            .filter(|u| !leased.contains(&u.outpoint) && !ignore(u));
        let selected = considered.next();
        let remaining = considered.count() as u64;
        let selected = selected.map(|utxo| {
            let lease = self.leases.take(vec![utxo.outpoint], owner);
            (utxo.outpoint, lease)
        });
        (selected, remaining)
    }

    /// Returns a predicate that accepts a reserved-wallet UTXO once it has more than
    /// `bury_depth` confirmations, or immediately when its transaction was composed by
    /// [`Self::create_reserved_utxos`] under [`GeneralUtxoPolicy::BuriedOnly`] with at least this
    /// burial depth.
    ///
    /// The set of such transactions is captured when the predicate is built; rebuild it after a
    /// refill whose outputs should qualify.
    pub fn settled(&self, bury_depth: u32) -> impl Fn(&UtxoInfo) -> bool {
        let funding_txids = self.funding_txids.clone();
        move |utxo| {
            utxo.confirmations > bury_depth
                || funding_txids
                    .get(&utxo.outpoint.txid)
                    .is_some_and(|input_depth| *input_depth >= bury_depth)
        }
    }

    // ── General-wallet pass-throughs with lease bookkeeping ────────────────

    /// Takes a lease on the first general-wallet UTXO that satisfies `predicate`, skipping
    /// CPFP anchors and held outpoints. Returns `None` when nothing matches.
    ///
    /// Unlike [`Self::fund_v3_transaction`], this hands back one chosen UTXO for callers that
    /// build a transaction around it. The unstaking-burn executor needs this, because its
    /// transaction has a fixed non-wallet first input that the outputs-only funding path
    /// cannot express.
    pub fn select_general_utxo(
        &self,
        owner: LeaseOwner,
        predicate: impl Fn(&UtxoInfo) -> bool,
    ) -> Option<(UtxoInfo, Lease)> {
        let exclude: BTreeSet<OutPoint> =
            self.exclude_anchors_and_leases(&[]).into_iter().collect();
        let selected = self
            .general
            .list_utxos()
            .into_iter()
            .find(|u| !exclude.contains(&u.outpoint) && predicate(u))?;
        let lease = self.leases.take(vec![selected.outpoint], owner);
        Some((selected, lease))
    }

    /// Funds an unsigned v3 transaction from the general wallet.
    ///
    /// Selects inputs from spendable general-wallet UTXOs, skipping anchors and held
    /// outpoints, signs them where the backend has key material, and returns the PSBT with a
    /// lease on the inputs.
    ///
    /// Callers of v3 paths must pass [`GeneralUtxoPolicy::ConfirmedOnly`]. TRUC (BIP-431)
    /// rejects a v3 transaction with an unconfirmed non-v3 ancestor, and it caps a v3
    /// transaction with an unconfirmed v3 ancestor to one parent and one child. A funding
    /// input from an unconfirmed UTXO therefore makes the transaction unrelayable in most
    /// mempool states.
    pub async fn fund_v3_transaction(
        &mut self,
        unsigned_tx: Transaction,
        fee_rate: FeeRate,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        let mut exclude = self.exclude_anchors_and_leases(&[]);
        self.apply_general_utxo_policy(general_utxo_policy, &mut exclude)?;
        let funded = self
            .general
            .fund_v3_transaction(unsigned_tx.output, None, fee_rate, &exclude)
            .await
            .map_err(Error::from_general)?;
        Ok(self.attach_lease(funded, owner))
    }

    /// Funds an unsigned v3 transaction using `inputs` as the explicit input set, normally a
    /// stored funding plan that a retry replays.
    pub async fn fund_v3_transaction_with_inputs(
        &mut self,
        unsigned_tx: Transaction,
        inputs: &[OutPoint],
        fee_rate: FeeRate,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        let funded = self
            .general
            .fund_v3_transaction(unsigned_tx.output, Some(inputs), fee_rate, &[])
            .await
            .map_err(Error::from_general)?;
        Ok(self.attach_lease(funded, owner))
    }

    /// Builds a CPFP child for `parent` spending the foreign-key output described by
    /// `anchor` plus inputs from this wallet to cover the child's share of the package fee.
    ///
    /// `parent_fee` is the caller-known fee already paid by `parent`; the backend uses it
    /// together with parent vbytes and `target_pkg_fee_rate` to compute the implied child
    /// fee.
    ///
    /// `replaced` describes the prior child that this build supersedes via RBF. Input
    /// selection exempts its inputs, so the new child can spend them again. The lease of the
    /// prior child is untouched: a failed build leaves it as it was, and the caller drops it
    /// once the new child supersedes the old one.
    ///
    /// `anchor_ownership` states whether the parent output at `anchor` belongs to this
    /// wallet. The returned lease covers the funding inputs, and covers the parent output
    /// only for [`AnchorOwnership::Wallet`].
    pub async fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        anchor_ownership: AnchorOwnership,
        target_pkg_fee_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<LeasedPsbt, Error> {
        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: anchor.vout(),
        };
        let exclude = self.exclude_anchors_and_leases(replaced.inputs);
        let funded = self
            .general
            .build_cpfp_child(
                parent,
                parent_fee,
                anchor,
                target_pkg_fee_rate,
                &exclude,
                replaced,
            )
            .await
            .map_err(Error::from_general)?;

        let mut held = funded.spent();
        if anchor_ownership == AnchorOwnership::Foreign {
            held.retain(|outpoint| *outpoint != anchor_outpoint);
        }
        let lease = self.leases.take(
            held,
            LeaseOwner::CpfpChild {
                parent: anchor_outpoint.txid,
            },
        );
        Ok(LeasedPsbt {
            psbt: funded.psbt,
            lease,
        })
    }

    // ── Cross-wallet (general → reserved) ──────────────────────────────────

    /// Creates a PSBT that funds `quantity` reserved-wallet UTXOs of `utxo_value` each,
    /// paying from the general wallet. The outputs go to the reserved-wallet script.
    ///
    /// The composer is agnostic of what `utxo_value` means to the caller — it only
    /// enforces that each output carries exactly that value and pays the reserved
    /// script. Callers wanting to top up a pool of equal-denomination UTXOs should query
    /// [`Self::reserved_utxos_with_value`] first and request only the delta they're
    /// missing; existing reserved-wallet UTXOs of the same `utxo_value` are
    /// automatically excluded from input selection so the composer doesn't re-spend pool
    /// members back to themselves. `general_utxo_policy` controls whether unconfirmed
    /// general-wallet UTXOs may be selected; a transaction funded under
    /// [`GeneralUtxoPolicy::BuriedOnly`] is recorded for [`Self::settled`].
    pub async fn create_reserved_utxos(
        &mut self,
        fee_rate: FeeRate,
        utxo_value: Amount,
        quantity: usize,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        // Exclude already-existing reserved UTXOs of the same value from selection so the
        // composer doesn't accidentally spend pool members back to itself.
        let existing: BTreeSet<OutPoint> = self
            .reserved_utxos_with_value(utxo_value)
            .into_iter()
            .map(|u| u.outpoint)
            .collect();

        let outputs = (0..quantity)
            .map(|_| TxOut {
                value: utxo_value,
                script_pubkey: self.reserved_script_pubkey.clone(),
            })
            .collect();

        let mut exclude = self.exclude_anchors_and_leases(&[]);
        exclude.extend(existing);

        self.apply_general_utxo_policy(general_utxo_policy, &mut exclude)?;

        let funded = self
            .general
            .fund_v3_transaction(outputs, None, fee_rate, &exclude)
            .await
            .map_err(Error::from_general)?;
        let leased = self.attach_lease(funded, owner);
        if let GeneralUtxoPolicy::BuriedOnly { bury_depth } = general_utxo_policy {
            self.funding_txids
                .insert(leased.psbt().unsigned_tx.compute_txid(), bury_depth);
        }
        Ok(leased)
    }

    // ── Sync ───────────────────────────────────────────────────────────────

    /// Syncs both wallets against their respective backends, persisting their staged chain state
    /// as it goes, and then prunes the lease set: any leased outpoint that neither wallet still
    /// holds is dropped (it was observed spent).
    pub async fn sync(&mut self) -> Result<(), Error> {
        let mut attempt = 0u32;
        loop {
            let mut err: Option<Error> = None;
            if let Err(e) = self.general.sync().await {
                err = Some(Error::from_general(e));
            }
            match self
                .reserved_sync_backend
                .sync_wallet(
                    &mut self.reserved,
                    &mut self.reserved_store,
                    self.config.persist_every_blocks,
                )
                .await
            {
                Ok(mempool) => self.reserved_mempool = mempool,
                Err(e) => err = Some(Error::Sync(e)),
            }
            match err {
                Some(e) => {
                    error!(?e, "error syncing wallet");
                    if attempt >= self.config.sync_retries {
                        return Err(e);
                    }
                    sleep(self.config.sync_base_delay * self.config.sync_backoff.pow(attempt))
                        .await;
                    attempt += 1;
                }
                None => break,
            }
        }

        // Prune stale leases. After a successful sync, drop any leased outpoint neither wallet
        // still holds — it was observed spent (the spend supersedes our lease bookkeeping). This
        // asks what the wallets hold, not what they will spend: an output the spendable filter
        // rejects may yet come back, and releasing its lease early would let a second caller take
        // an outpoint the first is still committed to.
        let live: BTreeSet<OutPoint> = self
            .general
            .unspent_outpoints()
            .into_iter()
            .chain(self.reserved.list_unspent().map(|lo| lo.outpoint))
            .collect();
        self.leases.retain_live(&live);
        Ok(())
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    /// Takes a lease on the inputs of `funded` and pairs the two.
    fn attach_lease(&self, funded: FundedPsbt, owner: LeaseOwner) -> LeasedPsbt {
        let lease = self.leases.take(funded.spent(), owner);
        LeasedPsbt {
            psbt: funded.psbt,
            lease,
        }
    }

    /// Applies `policy` to a funding exclusion set.
    ///
    /// [`GeneralUtxoPolicy::ConfirmedOnly`] and [`GeneralUtxoPolicy::BuriedOnly`] add every
    /// general-wallet UTXO at or below the required depth to `exclude`. When that leaves no
    /// eligible candidate at all, this returns [`Error::NoConfirmedGeneralUtxos`] or
    /// [`Error::NoBuriedGeneralUtxos`] so the caller reports a clear cause instead of a generic
    /// selection failure. [`GeneralUtxoPolicy::IncludeUnconfirmed`] changes nothing.
    fn apply_general_utxo_policy(
        &self,
        policy: GeneralUtxoPolicy,
        exclude: &mut Vec<OutPoint>,
    ) -> Result<(), Error> {
        let required_depth = match policy {
            GeneralUtxoPolicy::IncludeUnconfirmed => return Ok(()),
            GeneralUtxoPolicy::ConfirmedOnly => 0,
            GeneralUtxoPolicy::BuriedOnly { bury_depth } => bury_depth,
        };
        let excluded: BTreeSet<OutPoint> = exclude.iter().copied().collect();
        let (eligible, ineligible): (Vec<UtxoInfo>, Vec<UtxoInfo>) = self
            .general
            .list_utxos()
            .into_iter()
            .filter(|u| !excluded.contains(&u.outpoint))
            .partition(|u| u.confirmations > required_depth);
        if eligible.is_empty() && !ineligible.is_empty() {
            let ineligible_count = ineligible.len();
            let ineligible_amount = ineligible
                .iter()
                .fold(Amount::ZERO, |total, u| total + u.amount);
            warn!(
                ineligible_count,
                %ineligible_amount,
                required_depth,
                "no sufficiently confirmed general-wallet UTXOs are available for funding"
            );
            if let GeneralUtxoPolicy::BuriedOnly { bury_depth } = policy {
                return Err(Error::NoBuriedGeneralUtxos { bury_depth });
            }
            return Err(Error::NoConfirmedGeneralUtxos {
                unconfirmed_count: ineligible_count,
                unconfirmed_amount: ineligible_amount,
            });
        }
        exclude.extend(ineligible.into_iter().map(|u| u.outpoint));
        Ok(())
    }

    /// Returns the general-wallet outpoints that input selection must skip: CPFP anchors,
    /// which are zero-confirmation outputs at the configured anchor value, and the outpoints
    /// that a lease holds.
    ///
    /// `exempt` names outpoints that stay selectable. The CPFP rebuild path passes the
    /// funding inputs of the child that the new child replaces.
    fn exclude_anchors_and_leases(&self, exempt: &[OutPoint]) -> Vec<OutPoint> {
        let utxos = self.general.list_utxos();
        let anchors = utxos
            .iter()
            .filter(|u| u.amount == self.config.cpfp_value && u.confirmations == 0)
            .map(|u| u.outpoint);
        anchors.chain(self.leases.held_excluding(exempt)).collect()
    }
}
