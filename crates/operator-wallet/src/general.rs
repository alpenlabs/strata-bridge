//! The `GeneralWallet` trait — abstraction over the part of an operator's funds that pays for
//! bridge operations (fronting withdrawals, CPFP, top-ups). The trait isolates the surface that
//! genuinely differs between backends: today the native BDK-backed wallet, tomorrow a Fireblocks
//! adapter.
//!
//! Everything that doesn't vary between backends — leasing, the reserved wallet, anchor
//! filtering, cross-wallet transaction construction — lives on the concrete
//! [`crate::OperatorWallet<G>`] composer that wraps a `GeneralWallet`.

pub mod native;

use std::error::Error as StdError;

use bdk_wallet::bitcoin::{Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Transaction, TxOut};

/// A backend that manages the operator's general-purpose Bitcoin funds.
///
/// Concrete implementations:
/// - [`native::NativeGeneralWallet`] — BDK-backed, descriptor-only (no key material). Signing is
///   delegated to the secret-service by the caller.
/// - Fireblocks adapter (forthcoming) — ECDSA signing via Fireblocks API.
///
/// The trait is intentionally narrow: it covers signing + UTXO discovery + transaction
/// construction for the general wallet only. Lease bookkeeping, the reserved wallet, and
/// anchor handling live on the composer.
///
/// # Signing contract
///
/// A backend signs inputs it has key material for. Inputs it leaves unsigned must be populated
/// with `witness_utxo` and `tap_internal_key` (or analogous fields) so the caller can sign
/// downstream — typically by routing the sighash through the secret service.
pub trait GeneralWallet: Send + Sync {
    /// Backend-specific error type.
    type Error: StdError + Send + Sync + 'static;

    /// Refreshes internal state from the underlying source (chain RPC for native, vault API for
    /// remote backends like Fireblocks). Idempotent.
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

    /// Builds and (where possible) signs a v3 TRUC funding transaction.
    ///
    /// * `outputs` — recipient outputs to fund. Change (if any) is appended.
    /// * `explicit_inputs` — when `Some`, only these outpoints are used as inputs. When `None`, the
    ///   backend selects inputs from its spendable UTXO set, skipping `exclude`.
    /// * `fee_rate` — target sat-per-vbyte for the transaction itself.
    /// * `exclude` — outpoints the backend must not select (anchors, currently-leased outpoints,
    ///   etc.). Ignored if `explicit_inputs` is `Some`.
    ///
    /// Inputs the backend has key material for are signed. Anything left unsigned must have
    /// `witness_utxo` (and `tap_internal_key` for Taproot inputs) populated.
    fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> impl std::future::Future<Output = Result<FundedPsbt, Self::Error>> + Send;

    /// Builds a v3 TRUC CPFP child for `parent`, spending the BIP-431 ephemeral anchor at
    /// `parent.output[anchor_vout]` plus one fee-paying input drawn from this wallet.
    ///
    /// * `target_pkg_fee_rate` — sat-per-vbyte target for the (parent, child) package as a whole.
    /// * `exclude` — fee-paying-input selection skips these outpoints. Used to avoid re-selecting
    ///   the funding input of a prior child being replaced via RBF.
    ///
    /// **The anchor input is never signed** — backends populate its `witness_utxo` and
    /// `tap_internal_key` and leave the caller to sign it via the secret service. The
    /// funding input is signed iff the backend holds its key material.
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
    /// The funded PSBT. Inputs the backend could sign are signed; the rest carry
    /// `witness_utxo` (and `tap_internal_key` for Taproot) for downstream signing.
    pub psbt: Psbt,
    /// Outpoints consumed as inputs to this PSBT. The caller leases these so they aren't
    /// re-selected by concurrent duties.
    pub spent: Vec<OutPoint>,
}

/// A snapshot of a single UTXO controlled by a [`GeneralWallet`] (or, by convention, the
/// reserved wallet that the [`crate::OperatorWallet`] composer manages internally).
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// On-chain outpoint of the UTXO.
    pub outpoint: OutPoint,
    /// Output amount.
    pub amount: Amount,
    /// Confirmations as of the most recent sync. `0` if unconfirmed.
    pub confirmations: u32,
    /// Output script.
    pub script_pubkey: ScriptBuf,
}

impl UtxoInfo {
    /// Reconstructs the [`TxOut`] this UTXO refers to.
    pub fn as_txout(&self) -> TxOut {
        TxOut {
            value: self.amount,
            script_pubkey: self.script_pubkey.clone(),
        }
    }
}
