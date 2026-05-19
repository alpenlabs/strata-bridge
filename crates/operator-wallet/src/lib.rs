//! Operator wallet — composition over a swappable [`GeneralWallet`] backend.
//!
//! The bridge node holds an `OperatorWallet<G>` where `G: GeneralWallet`. The composer
//! manages:
//! - the always-native reserved wallet (BDK descriptor-only, signing via secret-service),
//! - the in-memory lease set (shared bookkeeping that doesn't differ between backends),
//! - anchor identification and exclusion,
//! - cross-wallet transaction construction (refill claim-funding pool, create stake funding tx).
//!
//! The `general` backend handles only what genuinely varies between native and Fireblocks:
//! its own UTXO discovery, its own signing, and its share of transaction building (funding,
//! CPFP child).
//!
//! Methods on [`OperatorWallet`] are `&mut self`. Callers serialize via an outer lock (today
//! `Arc<RwLock<OperatorWallet<_>>>` in `bridge-exec`) which also lets the executor span
//! multi-step critical sections (e.g. DB-lookup-then-fund-then-persist).

pub mod general;
pub mod sync;

use std::{collections::BTreeSet, time::Duration};

use bdk_wallet::{
    bitcoin::{Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, XOnlyPublicKey},
    chain::ChainPosition,
    descriptor, KeychainKind, Wallet,
};
use thiserror::Error;
use tokio::time::sleep;
use tracing::{error, info, warn};

pub use crate::general::{native::NativeGeneralWallet, FundedPsbt, GeneralWallet, UtxoInfo};
use crate::sync::{Backend, SyncError};

/// How many times we should reattempt after an error during a wallet sync.
const SYNC_RETRIES: u32 = 5;
/// The wallet will delay a retry by SYNC_BASE_DELAY * SYNC_BACKOFF.pow(current_retry).
const SYNC_BACKOFF: u32 = 3;
const SYNC_BASE_DELAY: Duration = Duration::from_millis(100);

/// Config for [`OperatorWallet`].
#[derive(Debug, Clone)]
pub struct OperatorWalletConfig {
    /// Value of the funding UTXO for stakes. Not the `s` connector value.
    stake_funding_utxo_value: Amount,
    /// Value of CPFP UTXOs to identify them.
    cpfp_value: Amount,
    /// Bitcoin network we're on.
    network: Network,
}

impl OperatorWalletConfig {
    /// Creates a new [`OperatorWalletConfig`].
    pub const fn new(
        stake_funding_utxo_value: Amount,
        cpfp_value: Amount,
        network: Network,
    ) -> Self {
        Self {
            stake_funding_utxo_value,
            cpfp_value,
            network,
        }
    }
}

/// Errors returned by [`OperatorWallet`] methods. Backend errors are boxed so call sites don't
/// have to be generic over `G::Error`.
#[derive(Debug, Error)]
pub enum Error {
    /// The general wallet backend reported an error.
    #[error("general wallet: {0}")]
    General(Box<dyn std::error::Error + Send + Sync>),
    /// BDK reported an error building a transaction on the reserved wallet.
    #[error("reserved wallet create-tx: {0}")]
    Reserved(#[from] bdk_wallet::error::CreateTxError),
    /// Reserved-wallet sync against the chain failed.
    #[error("reserved wallet sync: {0:?}")]
    Sync(SyncError),
}

impl Error {
    fn from_general<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::General(Box::new(e))
    }
}

/// The operator's wallet, composing a swappable general-wallet backend with the always-native
/// reserved wallet, lease bookkeeping, and cross-wallet transaction construction.
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
    /// Constructs a new [`OperatorWallet`] from a [`GeneralWallet`] backend and a native
    /// reserved-wallet pubkey. `initial_leases` is the set of outpoints to seed the lease
    /// state with (typically rehydrated from FDB at startup).
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

    /// Marks each of `outpoints` as leased.
    pub fn lease(&mut self, outpoints: &[OutPoint]) {
        for outpoint in outpoints {
            self.leased_outpoints.insert(*outpoint);
        }
    }

    /// Removes each of `outpoints` from the lease set. Logs (at `warn`) but does not error
    /// when a given outpoint wasn't leased — releases are idempotent.
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

    // ── Reserved-wallet operations ─────────────────────────────────────────

    /// Returns the reserved-wallet UTXOs that match the claim-funding value (i.e. the dust
    /// pool used to fund claim transactions).
    pub fn claim_funding_outputs(&self) -> Vec<UtxoInfo> {
        let tip = self.reserved.latest_checkpoint().height();
        self.reserved
            .list_unspent()
            .filter(|utxo| utxo.txout.value == self.config.stake_funding_utxo_value)
            .map(|lo| UtxoInfo {
                outpoint: lo.outpoint,
                amount: lo.txout.value,
                confirmations: match &lo.chain_position {
                    ChainPosition::Confirmed { anchor, .. } => {
                        tip.saturating_sub(anchor.block_id.height).saturating_add(1)
                    }
                    ChainPosition::Unconfirmed { .. } => 0,
                },
                script_pubkey: lo.txout.script_pubkey.clone(),
            })
            .collect()
    }

    /// Selects an unleased claim-funding UTXO that the `ignore` predicate doesn't reject,
    /// leases it, and returns it along with the remaining count.
    pub fn claim_funding_utxo(
        &mut self,
        ignore: impl Fn(&UtxoInfo) -> bool,
    ) -> (Option<OutPoint>, u64) {
        let available = self.claim_funding_outputs();
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
        self.lease(&funded.spent);
        Ok(funded)
    }

    /// Funds an unsigned v3 transaction using `inputs` as the input set (typically a
    /// previously-persisted funding plan being replayed on retry).
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
        self.lease(&funded.spent);
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
        let funded = self
            .general
            .build_cpfp_child(parent, anchor_vout, target_pkg_fee_rate, &exclude)
            .await
            .map_err(Error::from_general)?;
        self.lease(&funded.spent);
        Ok(funded)
    }

    // ── Cross-wallet (general → reserved) ──────────────────────────────────

    /// Creates a PSBT that refills the pool of claim-funding UTXOs in the reserved wallet by
    /// sending `stake_funding_utxo_value`-sized outputs from the general wallet to the
    /// reserved script. The returned PSBT still needs signing for any inputs the backend
    /// couldn't sign.
    pub async fn refill_claim_funding_utxos(
        &mut self,
        fee_rate: FeeRate,
        target_size: usize,
    ) -> Result<FundedPsbt, Error> {
        let claim_funding_outpoints: BTreeSet<OutPoint> = self
            .claim_funding_outputs()
            .into_iter()
            .map(|u| u.outpoint)
            .collect();
        let current_size = claim_funding_outpoints.len();
        let batch_size = target_size.saturating_sub(current_size);

        let outputs = (0..batch_size)
            .map(|_| TxOut {
                value: self.config.stake_funding_utxo_value,
                script_pubkey: self.reserved_script_pubkey.clone(),
            })
            .collect();

        let mut exclude = self.exclude_anchors_and_leases();
        exclude.extend(claim_funding_outpoints);

        let funded = self
            .general
            .fund_v3_transaction(outputs, None, fee_rate, &exclude)
            .await
            .map_err(Error::from_general)?;
        self.lease(&funded.spent);
        Ok(funded)
    }

    /// Creates a PSBT that funds a stake-chain transaction by paying `funding_amount` from
    /// the general wallet into the reserved script.
    pub async fn create_stake_funding_tx(
        &mut self,
        fee_rate: FeeRate,
        funding_amount: Amount,
    ) -> Result<FundedPsbt, Error> {
        let outputs = vec![TxOut {
            value: funding_amount,
            script_pubkey: self.reserved_script_pubkey.clone(),
        }];
        let exclude = self.exclude_anchors_and_leases();
        let funded = self
            .general
            .fund_v3_transaction(outputs, None, fee_rate, &exclude)
            .await
            .map_err(Error::from_general)?;
        self.lease(&funded.spent);
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
                    if attempt >= SYNC_RETRIES {
                        return Err(e);
                    }
                    sleep(SYNC_BASE_DELAY * SYNC_BACKOFF.pow(attempt)).await;
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
    /// selection: anchors (zero/dust-value unconfirmed outputs we keep around for fee
    /// bumping) plus currently-leased outpoints.
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
