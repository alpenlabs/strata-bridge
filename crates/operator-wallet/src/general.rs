//! The [`GeneralWallet`] trait — abstraction over the operator's general-purpose funds
//! (the wallet that fronts payments, pays CPFP fees, and tops up other internal pools).
//! The trait isolates the surface that genuinely varies between backends; concrete
//! implementations live in submodules.
//!
//! Everything that doesn't vary between backends — leasing, the reserved wallet, anchor
//! filtering, cross-wallet transaction construction — lives on the composer
//! [`crate::OperatorWallet<G>`] that wraps a `GeneralWallet`.

pub mod native;

use std::error::Error as StdError;

use bdk_wallet::{
    bitcoin::{Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction, TxOut},
    chain::ChainPosition,
};

/// A backend that manages the operator's general-purpose Bitcoin funds.
///
/// The trait is intentionally narrow: it covers UTXO discovery + signing + transaction
/// construction for the general wallet only. Lease bookkeeping, the reserved wallet, and
/// anchor handling live on the composer.
///
/// # Signing contract
///
/// A backend signs the inputs it has key material for. Inputs it leaves unsigned must
/// carry `witness_utxo` (and `tap_internal_key` for Taproot key-path) so the caller can
/// sign them downstream by whatever means it sees fit.
pub trait GeneralWallet: Send + Sync {
    /// Backend-specific error type.
    type Error: StdError + Send + Sync + 'static;

    /// Refreshes internal state from the underlying source. Idempotent.
    ///
    /// Takes `&mut self` because the typical native impl needs to mutate its BDK wallet
    /// state. Callers serialize via an outer lock; the trait doesn't impose interior
    /// mutability.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Returns the receive script for this wallet. Stable across calls for native backends;
    /// may rotate for backends that mint fresh deposit addresses per call.
    fn script_pubkey(&self) -> ScriptBuf;

    /// Returns every UTXO this wallet currently controls (confirmed and unconfirmed). The
    /// caller is responsible for filtering anchors, leases, and other domain-specific
    /// exclusions before requesting funding.
    fn list_utxos(&self) -> Vec<UtxoInfo>;

    /// Builds a v3 TRUC funding transaction and signs the inputs it has key material for.
    ///
    /// * `outputs` — recipient outputs to fund. Change (if any) is appended.
    /// * `explicit_inputs` — when `Some`, only these outpoints are used as inputs. When `None`, the
    ///   backend selects inputs from its spendable UTXO set, skipping `exclude`.
    /// * `fee_rate` — target sat-per-vbyte for the transaction itself.
    /// * `exclude` — outpoints the backend must not select (anchors, currently-leased outpoints,
    ///   etc.). Ignored when `explicit_inputs` is `Some`.
    ///
    /// Inputs the backend can sign are returned with their witnesses populated; the rest
    /// carry `witness_utxo` and `tap_internal_key` (for Taproot) so the caller can sign
    /// downstream.
    fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> impl std::future::Future<Output = Result<FundedPsbt, Self::Error>> + Send;

    /// Builds a v3 TRUC CPFP child for `parent`, spending the keyed-Taproot anchor at
    /// `parent.output[anchor_vout]` plus one fee-paying input drawn from this wallet.
    ///
    /// * `target_pkg_fee_rate` — sat-per-vbyte target for the (parent, child) package as a whole.
    /// * `exclude` — fee-paying-input selection skips these outpoints. Used to avoid re-selecting
    ///   the funding input of a prior child being replaced via RBF.
    ///
    /// Per the trait-level signing contract, the anchor input is left unsigned with
    /// `witness_utxo` and `tap_internal_key` populated; the fee-paying input is signed iff
    /// the backend holds its key material.
    fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        anchor_vout: u32,
        target_pkg_fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> impl std::future::Future<Output = Result<FundedPsbt, Self::Error>> + Send;
}

/// A funded PSBT returned by [`GeneralWallet`] funding operations.
#[derive(Debug, Clone)]
pub struct FundedPsbt {
    /// The funded PSBT. See the [`GeneralWallet`] signing contract for which inputs are
    /// signed vs. left for downstream signing.
    pub psbt: Psbt,
}

impl FundedPsbt {
    /// Returns the outpoints consumed as inputs to this PSBT, derived from
    /// `psbt.unsigned_tx`. Use this to lease the spent UTXOs against re-selection by
    /// concurrent callers.
    pub fn spent(&self) -> Vec<OutPoint> {
        self.psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect()
    }
}

/// A snapshot of a single UTXO controlled by a [`GeneralWallet`] (or, by convention, the
/// reserved wallet that the [`crate::OperatorWallet`] composer manages internally).
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// Outpoint identifying this UTXO.
    pub outpoint: OutPoint,
    /// Output amount.
    pub amount: Amount,
    /// Confirmations as of the most recent sync. `0` if the UTXO is in the mempool only
    /// (not yet on chain).
    pub confirmations: u32,
    /// Output script.
    pub script_pubkey: ScriptBuf,
}

impl From<UtxoInfo> for TxOut {
    fn from(u: UtxoInfo) -> Self {
        Self {
            value: u.amount,
            script_pubkey: u.script_pubkey,
        }
    }
}

impl From<&UtxoInfo> for TxOut {
    fn from(u: &UtxoInfo) -> Self {
        Self {
            value: u.amount,
            script_pubkey: u.script_pubkey.clone(),
        }
    }
}

/// Converts a BDK [`bdk_wallet::LocalOutput`] into a backend-neutral [`UtxoInfo`], computing
/// confirmations against `tip_height`. Shared between the native general-wallet backend and
/// the composer's reserved-wallet lookup since both are BDK-backed.
pub(crate) fn local_output_to_utxo_info(lo: &bdk_wallet::LocalOutput, tip_height: u32) -> UtxoInfo {
    let confirmations = match &lo.chain_position {
        ChainPosition::Confirmed { anchor, .. } => tip_height
            .saturating_sub(anchor.block_id.height)
            .saturating_add(1),
        ChainPosition::Unconfirmed { .. } => 0,
    };
    UtxoInfo {
        outpoint: lo.outpoint,
        amount: lo.txout.value,
        confirmations,
        script_pubkey: lo.txout.script_pubkey.clone(),
    }
}
