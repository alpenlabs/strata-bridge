//! The [`OperatorWallet`] composer.
//!
//! Composes a swappable [`crate::GeneralWallet`] backend with an always-native reserved wallet
//! and shared lease bookkeeping. The composer owns:
//!
//! - the BDK descriptor-only reserved wallet (signed downstream by the caller),
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
//! Only [`OperatorWallet::sync`] takes `&mut self`. Every other method takes `&self`, so a
//! caller holds a shared outer lock to fund a transaction, and a read of the wallet does not
//! queue behind a backend round trip that takes seconds. An internal lock serializes the
//! paths that select UTXOs, so two of them cannot pick one outpoint twice.
//!
//! Callers still take the exclusive outer lock for a multi-step critical section, such as a
//! database lookup, then funding, then a write.

use std::{collections::BTreeSet, sync::Arc, time::Instant};

use bdk_wallet::{
    bitcoin::{
        Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Witness, XOnlyPublicKey,
    },
    descriptor, KeychainKind, Wallet,
};
use tokio::{sync::Mutex as TokioMutex, time::sleep};
use tracing::{error, info, warn};

use crate::{
    config::OperatorWalletConfig,
    general::{
        local_output_to_utxo_info, AnchorInfo, AnchorOwnership, FundedPsbt, GeneralWallet,
        ReplacedChild, UtxoInfo,
    },
    leases::{Lease, LeaseOwner, LeaseSet},
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

/// Whether general-wallet funding may spend unconfirmed UTXOs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralUtxoPolicy {
    /// Allow the general wallet backend to select confirmed or unconfirmed UTXOs.
    IncludeUnconfirmed,
    /// Exclude unconfirmed general-wallet UTXOs from automatic input selection.
    ConfirmedOnly,
}

/// The operator's wallet: a [`GeneralWallet`] backend composed with the always-native reserved
/// wallet, shared lease bookkeeping, and cross-wallet transaction construction helpers.
#[derive(Debug)]
pub struct OperatorWallet<G: GeneralWallet> {
    general: G,
    reserved: Wallet,
    reserved_sync_backend: Backend,
    reserved_script_pubkey: ScriptBuf,
    config: OperatorWalletConfig,
    leases: Arc<LeaseSet>,
    /// Serializes every path that selects UTXOs and then takes a lease on them.
    ///
    /// A selection reads the set of held outpoints, awaits the backend, and takes the lease
    /// when the backend returns. Two selections that overlap read the same set, so they pick
    /// one outpoint twice and build two transactions that conflict. This lock makes the read,
    /// the selection, and the lease one step.
    ///
    /// It is a `tokio` mutex because the backend selection is a future. It replaces the
    /// exclusive outer lock that callers held for the same reason, so a read of the wallet no
    /// longer queues behind a backend round trip that takes seconds.
    ///
    /// A path with no await between the read and the lease is atomic without this lock. Those
    /// paths take it as well, so that an await added to one of them later cannot open the gap
    /// without notice.
    funding: TokioMutex<()>,
    /// Outcome and time of the most recent general-backend sync attempt. `None` before
    /// the first attempt. Kept per-backend because the reserved wallet's chain tip
    /// advances even while the general backend fails every sync (the two sync
    /// independently inside [`Self::sync`]), so the tip alone cannot represent
    /// general-backend health. The timestamp lets the probe report a stale verdict as
    /// degraded: syncs are duty-driven, so an old success on an idle bridge is a weaker
    /// signal than a fresh one.
    last_general_sync: Option<(bool, Instant)>,
}

impl<G: GeneralWallet> OperatorWallet<G> {
    /// Constructs an [`OperatorWallet`] from a [`GeneralWallet`] backend and a reserved-wallet
    /// pubkey. `initial_leases` is the set of outpoints to seed the lease state with,
    /// normally read from durable storage at startup. They enter as one committed lease
    /// under [`LeaseOwner::Rehydrated`], because the duty that took the original lease ran in
    /// an earlier process.
    pub fn new(
        general: G,
        reserved_pubkey: XOnlyPublicKey,
        config: OperatorWalletConfig,
        reserved_sync_backend: Backend,
        initial_leases: BTreeSet<OutPoint>,
    ) -> Self {
        let (reserved_desc, ..) =
            descriptor!(tr(reserved_pubkey)).expect("valid tr() descriptor for reserved");
        let reserved_wallet = Wallet::create_single(reserved_desc)
            .network(config.network)
            .create_wallet_no_persist()
            .expect("reserved wallet creation must not fail");
        let reserved_addr = reserved_wallet
            .peek_address(KeychainKind::External, 0)
            .address;
        info!("reserved wallet address: {reserved_addr}");
        let reserved_script_pubkey = reserved_addr.script_pubkey();
        Self {
            general,
            reserved: reserved_wallet,
            reserved_sync_backend,
            reserved_script_pubkey,
            config,
            leases: Arc::new(LeaseSet::with_committed(initial_leases)),
            funding: TokioMutex::new(()),
            last_general_sync: None,
        }
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

    /// Returns the BOSD descriptor where bridge payouts to this operator should be directed.
    /// Delegates to the backend so the destination matches the custodian that can spend it
    /// (native general-key P2TR vs. Fireblocks vault P2WPKH). See
    /// [`GeneralWallet::payout_descriptor`].
    pub fn payout_descriptor(&self) -> bitcoin_bosd::Descriptor {
        self.general.payout_descriptor()
    }

    /// Returns the reserved wallet's receive script.
    pub fn reserved_script_pubkey(&self) -> ScriptBuf {
        self.reserved_script_pubkey.clone()
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
    pub async fn lease_committed(&self, outpoints: Vec<OutPoint>, owner: LeaseOwner) {
        // Under the funding lock: a selection that is awaiting its backend computed its
        // exclusion set already, and a commit that lands between that read and the backend's
        // return hands the same outpoints to two spenders.
        let _funding = self.funding.lock().await;
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
    /// lock without serializing against wallet-dependent duties. The tip covers the reserved
    /// wallet only: the general backend syncs independently inside [`sync`](Self::sync) and
    /// can fail while this tip advances — probe [`Self::last_general_sync`] for it.
    pub fn local_chain_tip_height(&self) -> u32 {
        self.reserved.latest_checkpoint().height()
    }

    /// Outcome and time of the most recent general-backend sync attempt, or `None` before
    /// the first.
    ///
    /// The reserved tip ([`Self::local_chain_tip_height`]) keeps advancing while the general
    /// backend fails, because the two backends sync independently. A health probe that reads
    /// only the tip therefore reports a dead general backend (bad Fireblocks credentials, an
    /// API outage) as healthy forever. This is the general backend's own signal.
    pub const fn last_general_sync(&self) -> Option<(bool, Instant)> {
        self.last_general_sync
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
            .filter(|utxo| utxo.txout.value == value)
            .map(|lo| local_output_to_utxo_info(&lo, tip))
            .collect()
    }

    /// Returns the reserved-wallet UTXO at `outpoint`, or `None` if the reserved wallet's
    /// unspent list does not contain it — it may be spent, or the wallet's view may be stale.
    ///
    /// Outpoint-keyed because the caller already holds a previously-reserved outpoint (e.g. a
    /// claim-funding UTXO recorded against a graph at construction time) and needs the matching
    /// `TxOut`, regardless of the value that UTXO was funded at — callers can't assume the
    /// current pool denomination matches an older reservation if the denomination is recomputed
    /// from live protocol state.
    pub fn reserved_utxo_at(&self, outpoint: OutPoint) -> Option<UtxoInfo> {
        let tip = self.reserved.latest_checkpoint().height();
        self.reserved
            .list_unspent()
            .find(|utxo| utxo.outpoint == outpoint)
            .map(|lo| local_output_to_utxo_info(&lo, tip))
    }

    /// Takes a lease on one free reserved-wallet UTXO of value `value` that the `ignore`
    /// predicate does not reject.
    ///
    /// Returns the selected UTXO with its lease, and the number of other matching free UTXOs
    /// left after the selection.
    pub async fn reserve_utxo_with_value(
        &self,
        value: Amount,
        owner: LeaseOwner,
        ignore: impl Fn(&UtxoInfo) -> bool,
    ) -> (Option<(OutPoint, Lease)>, u64) {
        let _funding = self.funding.lock().await;
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

    // ── General-wallet pass-throughs with lease bookkeeping ────────────────

    /// Takes a lease on the first general-wallet UTXO that satisfies `predicate`, skipping
    /// CPFP anchors and held outpoints. Returns `None` when nothing matches.
    ///
    /// Unlike [`Self::fund_v3_transaction`], this hands back one chosen UTXO for callers that
    /// build a transaction around it. The unstaking-burn executor needs this, because its
    /// transaction has a fixed non-wallet first input that the outputs-only funding path
    /// cannot express.
    pub async fn select_general_utxo(
        &self,
        owner: LeaseOwner,
        predicate: impl Fn(&UtxoInfo) -> bool,
    ) -> Option<(UtxoInfo, Lease)> {
        let _funding = self.funding.lock().await;
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
        &self,
        unsigned_tx: Transaction,
        fee_rate: FeeRate,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        let _funding = self.funding.lock().await;
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
        &self,
        unsigned_tx: Transaction,
        inputs: &[OutPoint],
        fee_rate: FeeRate,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        let _funding = self.funding.lock().await;
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
        &self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        anchor_ownership: AnchorOwnership,
        target_pkg_fee_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<LeasedPsbt, Error> {
        let _funding = self.funding.lock().await;
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

    /// Signs the general-wallet-owned inputs of `tx` at `input_indices`. Returns a witness per
    /// index for inputs the backend can sign (e.g. Fireblocks), or `None` for inputs the caller
    /// must sign downstream (the native descriptor-only backend returns all `None`). See
    /// [`GeneralWallet::sign_owned_inputs`]. `prevouts[i]` is the output spent by `tx.input[i]`.
    pub async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, Error> {
        self.general
            .sign_owned_inputs(tx, input_indices, prevouts)
            .await
            .map_err(Error::from_general)
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
    /// general-wallet UTXOs may be selected.
    pub async fn create_reserved_utxos(
        &self,
        fee_rate: FeeRate,
        utxo_value: Amount,
        quantity: usize,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        // Exclude already-existing reserved UTXOs of the same value from selection so the
        // composer doesn't accidentally spend pool members back to itself.
        let _funding = self.funding.lock().await;
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
        Ok(self.attach_lease(funded, owner))
    }

    // ── Sync ───────────────────────────────────────────────────────────────

    /// Syncs both wallets against their respective backends and then prunes the lease set:
    /// any leased outpoint that is no longer in either wallet's spendable UTXO set is
    /// dropped (it was observed spent on-chain).
    pub async fn sync(&mut self) -> Result<(), Error> {
        let mut attempt = 0u32;
        loop {
            let mut err: Option<Error> = None;
            let general_result = self.general.sync().await;
            self.last_general_sync = Some((general_result.is_ok(), Instant::now()));
            if let Err(e) = general_result {
                err = Some(Error::from_general(e));
            }
            if let Err(e) = self
                .reserved_sync_backend
                .sync_wallet(&mut self.reserved)
                .await
            {
                err = Some(Error::Sync(e));
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

        // Prune stale leases. After a successful sync, drop each held outpoint that left the
        // spendable set of both wallets. That outpoint was spent on chain, and the on-chain
        // spend supersedes the local bookkeeping.
        let live: BTreeSet<OutPoint> = self
            .general
            .list_utxos()
            .into_iter()
            .map(|u| u.outpoint)
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
    /// For [`GeneralUtxoPolicy::ConfirmedOnly`], this adds every unconfirmed general-wallet
    /// UTXO to `exclude`. When that leaves no confirmed candidate at all, it returns
    /// [`Error::NoConfirmedGeneralUtxos`] so the caller reports a clear cause instead of a
    /// generic selection failure. [`GeneralUtxoPolicy::IncludeUnconfirmed`] changes nothing.
    fn apply_general_utxo_policy(
        &self,
        policy: GeneralUtxoPolicy,
        exclude: &mut Vec<OutPoint>,
    ) -> Result<(), Error> {
        if policy != GeneralUtxoPolicy::ConfirmedOnly {
            return Ok(());
        }
        let excluded: BTreeSet<OutPoint> = exclude.iter().copied().collect();
        let (confirmed, unconfirmed): (Vec<UtxoInfo>, Vec<UtxoInfo>) = self
            .general
            .list_utxos()
            .into_iter()
            .filter(|u| !excluded.contains(&u.outpoint))
            .partition(|u| u.confirmations > 0);
        if confirmed.is_empty() && !unconfirmed.is_empty() {
            let unconfirmed_count = unconfirmed.len();
            let unconfirmed_amount = unconfirmed
                .iter()
                .fold(Amount::ZERO, |total, u| total + u.amount);
            warn!(
                unconfirmed_count,
                %unconfirmed_amount,
                "no confirmed general-wallet UTXOs are available for funding"
            );
            return Err(Error::NoConfirmedGeneralUtxos {
                unconfirmed_count,
                unconfirmed_amount,
            });
        }
        exclude.extend(unconfirmed.into_iter().map(|u| u.outpoint));
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
