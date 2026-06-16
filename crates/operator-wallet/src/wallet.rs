//! The [`OperatorWallet`] composer.
//!
//! Composes a swappable [`crate::GeneralWallet`] backend with an always-native reserved wallet
//! and shared in-memory lease bookkeeping. The composer owns:
//!
//! - the BDK descriptor-only reserved wallet (signed downstream by the caller),
//! - the lease set shared across both wallets,
//! - anchor exclusion during input selection,
//! - cross-wallet construction helpers that produce PSBTs paying from the general wallet into
//!   reserved-wallet outputs of a caller-specified denomination.
//!
//! Methods on [`OperatorWallet`] take `&mut self`; callers serialize via an outer lock when
//! they need a multi-step critical section (e.g. DB-lookup-then-fund-then-persist).

use std::collections::BTreeSet;

use bdk_wallet::{
    bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Transaction, TxOut, XOnlyPublicKey},
    descriptor, KeychainKind, Wallet,
};
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::{
    config::OperatorWalletConfig,
    general::{local_output_to_utxo_info, FundedPsbt, GeneralWallet, UtxoInfo},
    sync::Backend,
    Error,
};

/// The operator's wallet: a [`GeneralWallet`] backend composed with the always-native reserved
/// wallet, shared lease bookkeeping, and cross-wallet transaction construction helpers.
#[derive(Debug)]
pub struct OperatorWallet<G: GeneralWallet> {
    general: G,
    reserved: Wallet,
    reserved_sync_backend: Backend,
    reserved_script_pubkey: ScriptBuf,
    config: OperatorWalletConfig,
    leased_outpoints: BTreeSet<OutPoint>,
}

impl<G: GeneralWallet> OperatorWallet<G> {
    /// Constructs an [`OperatorWallet`] from a [`GeneralWallet`] backend and a reserved-wallet
    /// pubkey. `initial_leases` is the set of outpoints to seed the lease state with
    /// (typically rehydrated from durable storage at startup).
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
            leased_outpoints: initial_leases,
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

    /// Returns the reserved wallet's receive script.
    pub fn reserved_script_pubkey(&self) -> ScriptBuf {
        self.reserved_script_pubkey.clone()
    }

    // ── Lease bookkeeping ───────────────────────────────────────────────────

    /// Returns the currently-leased outpoints.
    pub const fn leased_outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.leased_outpoints
    }

    /// Marks each of `outpoints` as leased. Safe to call with already-leased outpoints
    /// (the set is idempotent).
    pub fn lease(&mut self, outpoints: &[OutPoint]) {
        for outpoint in outpoints {
            self.leased_outpoints.insert(*outpoint);
        }
    }

    /// Removes each of `outpoints` from the lease set. Safe to call repeatedly or with
    /// outpoints that were never leased.
    pub fn release(&mut self, outpoints: &[OutPoint]) {
        for outpoint in outpoints {
            if !self.leased_outpoints.remove(outpoint) {
                warn!(
                    ?outpoint,
                    "attempted to release outpoint that was not leased"
                );
            }
        }
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

    /// Selects and leases one unleased reserved-wallet UTXO of value `value` that the
    /// `ignore` predicate doesn't reject. Returns the selected outpoint (if any) and the
    /// number of *additional* matching UTXOs left after the selection.
    pub fn reserve_utxo_with_value(
        &mut self,
        value: Amount,
        ignore: impl Fn(&UtxoInfo) -> bool,
    ) -> (Option<OutPoint>, u64) {
        let available = self.reserved_utxos_with_value(value);
        let leased = &self.leased_outpoints;
        let mut considered = available
            .into_iter()
            .filter(|u| !leased.contains(&u.outpoint) && !ignore(u));
        let selected = considered.next();
        let remaining = considered.count() as u64;
        if let Some(ref utxo) = selected {
            self.leased_outpoints.insert(utxo.outpoint);
        }
        (selected.map(|u| u.outpoint), remaining)
    }

    // ── General-wallet pass-throughs with lease bookkeeping ────────────────

    /// Selects the first general-wallet UTXO that satisfies `predicate`, excluding CPFP
    /// anchors and currently-leased outpoints, leases it so concurrent duties don't
    /// re-select the same outpoint, and returns it. Returns `None` if nothing matches.
    ///
    /// Unlike [`Self::fund_v3_transaction`], this hands back a single chosen UTXO for callers
    /// that build a bespoke transaction around it — e.g. the unstaking-burn executor, whose tx
    /// has a fixed non-wallet first input that the generic outputs-only funding path can't
    /// express.
    pub fn select_and_lease_general_utxo(
        &mut self,
        predicate: impl Fn(&UtxoInfo) -> bool,
    ) -> Option<UtxoInfo> {
        let exclude: BTreeSet<OutPoint> = self.exclude_anchors_and_leases().into_iter().collect();
        let selected = self
            .general
            .list_utxos()
            .into_iter()
            .find(|u| !exclude.contains(&u.outpoint) && predicate(u))?;
        self.lease(&[selected.outpoint]);
        Some(selected)
    }

    /// Funds an unsigned v3 transaction from the general wallet.
    ///
    /// Selects inputs from spendable general-wallet UTXOs (excluding anchors and currently-
    /// leased outpoints), signs them where the backend has key material, and returns a
    /// [`FundedPsbt`]. The consumed inputs are leased before return.
    pub async fn fund_v3_transaction(
        &mut self,
        unsigned_tx: Transaction,
        fee_rate: FeeRate,
    ) -> Result<FundedPsbt, Error> {
        let exclude = self.exclude_anchors_and_leases();
        let funded = self
            .general
            .fund_v3_transaction(unsigned_tx.output, None, fee_rate, &exclude)
            .await
            .map_err(Error::from_general)?;
        self.lease(&funded.spent());
        Ok(funded)
    }

    /// Funds an unsigned v3 transaction using `inputs` as the explicit input set (typically
    /// a previously-persisted funding plan being replayed on retry).
    pub async fn fund_v3_transaction_with_inputs(
        &mut self,
        unsigned_tx: Transaction,
        inputs: &[OutPoint],
        fee_rate: FeeRate,
    ) -> Result<FundedPsbt, Error> {
        let funded = self
            .general
            .fund_v3_transaction(unsigned_tx.output, Some(inputs), fee_rate, &[])
            .await
            .map_err(Error::from_general)?;
        self.lease(&funded.spent());
        Ok(funded)
    }

    /// Builds a CPFP child for `parent` spending the anchor at `anchor_vout`.
    ///
    /// `replacing`, when `Some`, identifies the funding outpoints of a prior child being
    /// replaced via RBF. Those outpoints are released from the lease set before
    /// fee-paying-input selection so they can be re-selected.
    pub async fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        anchor_vout: u32,
        target_pkg_fee_rate: FeeRate,
        replacing: Option<&[OutPoint]>,
    ) -> Result<FundedPsbt, Error> {
        if let Some(prior) = replacing {
            self.release(prior);
        }
        let exclude = self.exclude_anchors_and_leases();
        match self
            .general
            .build_cpfp_child(parent, anchor_vout, target_pkg_fee_rate, &exclude)
            .await
        {
            Ok(funded) => {
                self.lease(&funded.spent());
                Ok(funded)
            }
            Err(e) => {
                // Restore the lease state torn down before selection so a retry observes the
                // same world. Without this, a backend failure silently un-leases the prior
                // child's funding inputs.
                if let Some(prior) = replacing {
                    self.lease(prior);
                }
                Err(Error::from_general(e))
            }
        }
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
    /// members back to themselves.
    pub async fn create_reserved_utxos(
        &mut self,
        fee_rate: FeeRate,
        utxo_value: Amount,
        quantity: usize,
    ) -> Result<FundedPsbt, Error> {
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

        let mut exclude = self.exclude_anchors_and_leases();
        exclude.extend(existing);

        let funded = self
            .general
            .fund_v3_transaction(outputs, None, fee_rate, &exclude)
            .await
            .map_err(Error::from_general)?;
        self.lease(&funded.spent());
        Ok(funded)
    }

    // ── Sync ───────────────────────────────────────────────────────────────

    /// Syncs both wallets against their respective backends and then prunes the lease set:
    /// any leased outpoint that is no longer in either wallet's spendable UTXO set is
    /// dropped (it was observed spent on-chain).
    pub async fn sync(&mut self) -> Result<(), Error> {
        let mut attempt = 0u32;
        loop {
            let mut err: Option<Error> = None;
            if let Err(e) = self.general.sync().await {
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

        // Prune stale leases. After a successful sync, drop any leased outpoint whose
        // underlying UTXO is no longer in either wallet's spendable set — it was observed
        // spent on-chain (the on-chain spend supersedes our local lease bookkeeping).
        let live: BTreeSet<OutPoint> = self
            .general
            .list_utxos()
            .into_iter()
            .map(|u| u.outpoint)
            .chain(self.reserved.list_unspent().map(|lo| lo.outpoint))
            .collect();
        self.leased_outpoints.retain(|o| live.contains(o));
        Ok(())
    }

    // ── Internal helpers ───────────────────────────────────────────────────

    /// Returns the set of general-wallet outpoints that should be excluded from input
    /// selection: CPFP anchors (zero-confirmation outputs at the configured anchor value)
    /// plus currently-leased outpoints.
    fn exclude_anchors_and_leases(&self) -> Vec<OutPoint> {
        let utxos = self.general.list_utxos();
        let anchors = utxos
            .iter()
            .filter(|u| u.amount == self.config.cpfp_value && u.confirmations == 0)
            .map(|u| u.outpoint);
        anchors
            .chain(self.leased_outpoints.iter().copied())
            .collect()
    }
}
