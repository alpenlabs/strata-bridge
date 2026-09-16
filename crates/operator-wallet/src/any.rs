//! Runtime-selected operator wallet backend.
//!
//! [`AnyOperatorWallet`] lets the binary hold a single, non-generic wallet handle (e.g. on
//! `OutputHandles`) while choosing the general-wallet backend — native BDK or Fireblocks — at
//! startup from config. It forwards the full [`OperatorWallet`] surface the executors use to
//! whichever variant is active; the Fireblocks variant is compiled only under the
//! `fireblocks` feature.
//!
//! Method receivers mirror [`OperatorWallet`]: `&self` for everything except
//! [`OperatorWallet::sync`], which needs `&mut self` because both backends' general-wallet
//! sync takes `&mut self`. The interior funding lock inside the wallet serializes selection,
//! so a caller that only funds
//! or builds holds a shared guard; only sync (and callers keeping the old multi-step critical
//! sections) take the exclusive guard.

use std::{collections::BTreeSet, time::Instant};

use bdk_wallet::bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Transaction, TxOut, Witness};

#[cfg(feature = "fireblocks")]
use crate::general::fireblocks::FireblocksGeneralWallet;
use crate::{
    general::{
        native::NativeGeneralWallet, AnchorInfo, AnchorOwnership, GeneralWallet, ReplacedChild,
        UtxoInfo,
    },
    Error, GeneralUtxoPolicy, Lease, LeaseOwner, LeasedPsbt, OperatorWallet,
};

/// An operator wallet whose general-wallet backend is selected at runtime.
// The two variants differ in size (each embeds a different `GeneralWallet` backend), but the
// handle is always held behind an `Arc<RwLock<…>>`, so the size delta never hits the stack.
#[cfg_attr(
    feature = "fireblocks",
    expect(
        clippy::large_enum_variant,
        reason = "always Arc<RwLock<>>-boxed; size delta is irrelevant"
    )
)]
#[derive(Debug)]
pub enum AnyOperatorWallet {
    /// Local BDK-backed general wallet (descriptor-only; signed downstream via secret-service).
    Native(OperatorWallet<NativeGeneralWallet>),
    /// Fireblocks-backed general wallet (RAW signing).
    #[cfg(feature = "fireblocks")]
    Fireblocks(OperatorWallet<FireblocksGeneralWallet>),
}

impl From<OperatorWallet<NativeGeneralWallet>> for AnyOperatorWallet {
    fn from(wallet: OperatorWallet<NativeGeneralWallet>) -> Self {
        Self::Native(wallet)
    }
}

#[cfg(feature = "fireblocks")]
impl From<OperatorWallet<FireblocksGeneralWallet>> for AnyOperatorWallet {
    fn from(wallet: OperatorWallet<FireblocksGeneralWallet>) -> Self {
        Self::Fireblocks(wallet)
    }
}

/// Dispatches `$body` against whichever backend variant is active, binding it to `$w`.
macro_rules! delegate {
    ($self:expr, $w:ident => $body:expr) => {
        match $self {
            Self::Native($w) => $body,
            #[cfg(feature = "fireblocks")]
            Self::Fireblocks($w) => $body,
        }
    };
}

impl AnyOperatorWallet {
    /// See [`OperatorWallet::general_script_pubkey`].
    pub fn general_script_pubkey(&self) -> ScriptBuf {
        delegate!(self, w => w.general_script_pubkey())
    }

    /// See [`OperatorWallet::payout_descriptor`].
    pub fn payout_descriptor(&self) -> bitcoin_bosd::Descriptor {
        delegate!(self, w => w.payout_descriptor())
    }

    /// See [`OperatorWallet::reserved_script_pubkey`].
    pub fn reserved_script_pubkey(&self) -> ScriptBuf {
        delegate!(self, w => w.reserved_script_pubkey())
    }

    /// See [`OperatorWallet::leased_outpoints`].
    pub fn leased_outpoints(&self) -> BTreeSet<OutPoint> {
        delegate!(self, w => w.leased_outpoints())
    }

    /// See [`OperatorWallet::lease_committed`].
    pub async fn lease_committed(&self, outpoints: Vec<OutPoint>, owner: LeaseOwner) {
        delegate!(self, w => w.lease_committed(outpoints, owner).await)
    }

    /// See [`OperatorWallet::release_committed`].
    pub fn release_committed(&self, outpoints: &[OutPoint]) {
        delegate!(self, w => w.release_committed(outpoints));
    }

    /// See [`OperatorWallet::reserved_utxos_with_value`].
    pub fn reserved_utxos_with_value(&self, value: Amount) -> Vec<UtxoInfo> {
        delegate!(self, w => w.reserved_utxos_with_value(value))
    }

    /// See [`OperatorWallet::local_chain_tip_height`].
    pub fn local_chain_tip_height(&self) -> u32 {
        delegate!(self, w => w.local_chain_tip_height())
    }

    /// See [`OperatorWallet::last_general_sync`].
    pub const fn last_general_sync(&self) -> Option<(bool, Instant)> {
        delegate!(self, w => w.last_general_sync())
    }

    /// See [`OperatorWallet::reserved_utxo_at`].
    pub fn reserved_utxo_at(&self, outpoint: OutPoint) -> Option<UtxoInfo> {
        delegate!(self, w => w.reserved_utxo_at(outpoint))
    }

    /// Lists the general wallet's UTXOs.
    ///
    /// Delegates to `GeneralWallet::list_utxos` on whichever backend is active. Exposed on the
    /// erased handle because `general()` returns a backend-specific type that callers holding an
    /// [`AnyOperatorWallet`] cannot name.
    pub fn list_general_utxos(&self) -> Vec<UtxoInfo> {
        delegate!(self, w => w.general().list_utxos())
    }

    /// See [`OperatorWallet::reserve_utxo_with_value`].
    pub async fn reserve_utxo_with_value(
        &self,
        value: Amount,
        owner: LeaseOwner,
        ignore: impl Fn(&UtxoInfo) -> bool,
    ) -> (Option<(OutPoint, Lease)>, u64) {
        delegate!(self, w => w.reserve_utxo_with_value(value, owner, ignore).await)
    }

    /// See [`OperatorWallet::select_general_utxo`].
    pub async fn select_general_utxo(
        &self,
        owner: LeaseOwner,
        predicate: impl Fn(&UtxoInfo) -> bool,
    ) -> Option<(UtxoInfo, Lease)> {
        delegate!(self, w => w.select_general_utxo(owner, predicate).await)
    }

    /// See [`OperatorWallet::fund_v3_transaction`].
    pub async fn fund_v3_transaction(
        &self,
        unsigned_tx: Transaction,
        fee_rate: FeeRate,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        delegate!(
            self,
            w => w
                .fund_v3_transaction(unsigned_tx, fee_rate, general_utxo_policy, owner)
                .await
        )
    }

    /// See [`OperatorWallet::fund_v3_transaction_with_inputs`].
    pub async fn fund_v3_transaction_with_inputs(
        &self,
        unsigned_tx: Transaction,
        inputs: &[OutPoint],
        fee_rate: FeeRate,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        delegate!(
            self,
            w => w
                .fund_v3_transaction_with_inputs(unsigned_tx, inputs, fee_rate, owner)
                .await
        )
    }

    /// See [`OperatorWallet::build_cpfp_child`].
    pub async fn build_cpfp_child(
        &self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        anchor_ownership: AnchorOwnership,
        target_pkg_fee_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<LeasedPsbt, Error> {
        delegate!(
            self,
            w => w
                .build_cpfp_child(
                    parent,
                    parent_fee,
                    anchor,
                    anchor_ownership,
                    target_pkg_fee_rate,
                    replaced,
                )
                .await
        )
    }

    /// See [`OperatorWallet::sign_owned_inputs`].
    pub async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, Error> {
        delegate!(self, w => w.sign_owned_inputs(tx, input_indices, prevouts).await)
    }

    /// See [`OperatorWallet::create_reserved_utxos`].
    pub async fn create_reserved_utxos(
        &self,
        fee_rate: FeeRate,
        utxo_value: Amount,
        quantity: usize,
        general_utxo_policy: GeneralUtxoPolicy,
        owner: LeaseOwner,
    ) -> Result<LeasedPsbt, Error> {
        delegate!(
            self,
            w => w
                .create_reserved_utxos(
                    fee_rate,
                    utxo_value,
                    quantity,
                    general_utxo_policy,
                    owner,
                )
                .await
        )
    }

    /// See [`OperatorWallet::sync`].
    pub async fn sync(&mut self) -> Result<(), Error> {
        delegate!(self, w => w.sync().await)
    }
}
