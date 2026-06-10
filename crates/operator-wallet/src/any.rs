//! Runtime-selected operator wallet backend.
//!
//! [`AnyOperatorWallet`] lets the binary hold a single, non-generic wallet handle (e.g. on
//! `OutputHandles`) while choosing the general-wallet backend — native BDK or Fireblocks — at
//! startup from config. It forwards the full [`OperatorWallet`] surface the executors use to
//! whichever variant is active; the Fireblocks variant is compiled only under the
//! `fireblocks` feature.

use std::collections::BTreeSet;

use bdk_wallet::bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Transaction, TxOut, Witness};

#[cfg(feature = "fireblocks")]
use crate::general::fireblocks::FireblocksGeneralWallet;
use crate::{
    general::{native::NativeGeneralWallet, AnchorInfo, FundedPsbt, UtxoInfo},
    Error, OperatorWallet,
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
    pub const fn leased_outpoints(&self) -> &BTreeSet<OutPoint> {
        delegate!(self, w => w.leased_outpoints())
    }

    /// See [`OperatorWallet::lease`].
    pub fn lease(&mut self, outpoints: &[OutPoint]) {
        delegate!(self, w => w.lease(outpoints));
    }

    /// See [`OperatorWallet::release`].
    pub fn release(&mut self, outpoints: &[OutPoint]) {
        delegate!(self, w => w.release(outpoints));
    }

    /// See [`OperatorWallet::reserved_utxos_with_value`].
    pub fn reserved_utxos_with_value(&self, value: Amount) -> Vec<UtxoInfo> {
        delegate!(self, w => w.reserved_utxos_with_value(value))
    }

    /// See [`OperatorWallet::reserved_utxo_at`].
    pub fn reserved_utxo_at(&self, outpoint: OutPoint) -> Option<UtxoInfo> {
        delegate!(self, w => w.reserved_utxo_at(outpoint))
    }

    /// See [`OperatorWallet::reserve_utxo_with_value`].
    pub fn reserve_utxo_with_value(
        &mut self,
        value: Amount,
        ignore: impl Fn(&UtxoInfo) -> bool,
    ) -> (Option<OutPoint>, u64) {
        delegate!(self, w => w.reserve_utxo_with_value(value, ignore))
    }

    /// See [`OperatorWallet::select_and_lease_general_utxo`].
    pub fn select_and_lease_general_utxo(
        &mut self,
        predicate: impl Fn(&UtxoInfo) -> bool,
    ) -> Option<UtxoInfo> {
        delegate!(self, w => w.select_and_lease_general_utxo(predicate))
    }

    /// See [`OperatorWallet::fund_v3_transaction`].
    pub async fn fund_v3_transaction(
        &mut self,
        unsigned_tx: Transaction,
        fee_rate: FeeRate,
    ) -> Result<FundedPsbt, Error> {
        delegate!(self, w => w.fund_v3_transaction(unsigned_tx, fee_rate).await)
    }

    /// See [`OperatorWallet::fund_v3_transaction_with_inputs`].
    pub async fn fund_v3_transaction_with_inputs(
        &mut self,
        unsigned_tx: Transaction,
        inputs: &[OutPoint],
        fee_rate: FeeRate,
    ) -> Result<FundedPsbt, Error> {
        delegate!(self, w => w.fund_v3_transaction_with_inputs(unsigned_tx, inputs, fee_rate).await)
    }

    /// See [`OperatorWallet::build_cpfp_child`].
    pub async fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        target_pkg_fee_rate: FeeRate,
        replacing: Option<&[OutPoint]>,
    ) -> Result<FundedPsbt, Error> {
        delegate!(self, w => w.build_cpfp_child(parent, parent_fee, anchor, target_pkg_fee_rate, replacing).await)
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
        &mut self,
        fee_rate: FeeRate,
        utxo_value: Amount,
        quantity: usize,
    ) -> Result<FundedPsbt, Error> {
        delegate!(self, w => w.create_reserved_utxos(fee_rate, utxo_value, quantity).await)
    }

    /// See [`OperatorWallet::sync`].
    pub async fn sync(&mut self) -> Result<(), Error> {
        delegate!(self, w => w.sync().await)
    }
}
