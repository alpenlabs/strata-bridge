//! Native BDK-backed implementation of [`GeneralWallet`].
//!
//! The native wallet holds the operator's general-funds descriptor (`tr(general_pubkey)`) but
//! never holds private keys. Per the [`GeneralWallet`] signing contract, every PSBT this impl
//! returns carries `witness_utxo` and `tap_internal_key` on its inputs but no signatures —
//! the caller signs downstream.

use std::collections::BTreeSet;

use bdk_wallet::{
    bitcoin::{
        psbt::Input as PsbtInput, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Transaction,
        TxOut, XOnlyPublicKey,
    },
    descriptor,
    error::CreateTxError,
    KeychainKind, TxOrdering, Wallet,
};
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    general::{local_output_to_utxo_info, AnchorInfo, FundedPsbt, GeneralWallet, UtxoInfo},
    sync::{Backend, SyncError},
};

/// Estimated witness weight (in weight units) for a Taproot key-path spend: 1 byte witness
/// count prefix + 1 byte witness element size prefix + 64 byte signature. Used by
/// [`build_cpfp_child`](NativeGeneralWallet::build_cpfp_child) to tell BDK how large the
/// anchor satisfaction will be for fee-rate computation. The sighash type byte is implicit
/// when sighash is `SIGHASH_DEFAULT` (it's omitted from the witness in that case).
const TAPROOT_KEY_PATH_SAT_WEIGHT: usize = 66;

/// Native BDK-backed general wallet.
#[derive(Debug)]
pub struct NativeGeneralWallet {
    /// Cached at construction; the BDK descriptor doesn't change at runtime.
    script_pubkey: ScriptBuf,
    /// The operator's general x-only key. Retained to derive the payout descriptor
    /// (`new_p2tr(general_pubkey)`), which is the untweaked-key P2TR — distinct from the
    /// BIP86-tweaked `script_pubkey` the BDK funding wallet watches.
    general_pubkey: XOnlyPublicKey,
    wallet: Wallet,
    sync_backend: Backend,
}

impl NativeGeneralWallet {
    /// Constructs a native general wallet from the operator's general x-only public key.
    pub fn new(general_pubkey: XOnlyPublicKey, network: Network, sync_backend: Backend) -> Self {
        let (desc, ..) = descriptor!(tr(general_pubkey)).expect("valid tr() descriptor");
        let wallet = Wallet::create_single(desc)
            .network(network)
            .create_wallet_no_persist()
            .expect("wallet creation must not fail");
        let address = wallet.peek_address(KeychainKind::External, 0).address;
        info!("general wallet address: {address}");
        let script_pubkey = address.script_pubkey();
        Self {
            script_pubkey,
            general_pubkey,
            wallet,
            sync_backend,
        }
    }
}

/// Error type for the native general wallet impl.
#[derive(Debug, Error)]
pub enum NativeGeneralError {
    /// BDK failed to build a transaction (insufficient funds, no UTXOs, ...).
    #[error("bdk create-tx: {0}")]
    CreateTx(#[from] CreateTxError),
    /// Chain sync (block / mempool fetch) failed.
    #[error("wallet sync: {0:?}")]
    Sync(SyncError),
    /// `anchor.vout` indexes past the end of `parent.output`.
    #[error("anchor vout {vout} out of range for parent with {parent_outputs} outputs")]
    AnchorVoutOutOfRange {
        /// The requested anchor vout.
        vout: u32,
        /// Number of outputs on `parent`.
        parent_outputs: usize,
    },
    /// BDK rejected the foreign-utxo insertion of the parent's anchor (typically because it
    /// could not parse the script_pubkey).
    #[error("bdk add_foreign_utxo for anchor: {0}")]
    AnchorForeignUtxo(String),
}

impl GeneralWallet for NativeGeneralWallet {
    type Error = NativeGeneralError;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        self.sync_backend
            .sync_wallet(&mut self.wallet)
            .await
            .map_err(NativeGeneralError::Sync)
    }

    fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey.clone()
    }

    fn payout_descriptor(&self) -> bitcoin_bosd::Descriptor {
        // Untweaked-key P2TR keyed to the operator's general key — matches the historical
        // payout descriptor and the key the CPFP `ParentTxCombined` path signs with.
        bitcoin_bosd::Descriptor::new_p2tr(&self.general_pubkey.serialize())
            .expect("operator general x-only pubkey is a valid P2TR payload")
    }

    fn list_utxos(&self) -> Vec<UtxoInfo> {
        let tip = self.wallet.latest_checkpoint().height();
        self.wallet
            .list_unspent()
            .map(|lo| local_output_to_utxo_info(&lo, tip))
            .collect()
    }

    async fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        let psbt = build_v3_psbt(
            &mut self.wallet,
            &outputs,
            explicit_inputs,
            fee_rate,
            exclude,
        )?;
        Ok(FundedPsbt { psbt })
    }

    async fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        parent_fee: Amount,
        anchor: AnchorInfo,
        target_pkg_fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        build_cpfp_child_impl(
            &mut self.wallet,
            parent,
            parent_fee,
            anchor,
            target_pkg_fee_rate,
            exclude,
        )
    }
}

/// Implementation of [`NativeGeneralWallet::build_cpfp_child`], factored into a free function
/// so it doesn't borrow `self` through the trait method and can be unit-tested without an
/// outer `NativeGeneralWallet`.
///
/// Hands BDK two facts:
///
/// 1. The anchor must be in the child via `add_foreign_utxo` — the wallet doesn't have the anchor
///    key, and the caller signs the resulting input downstream. We set `witness_utxo` +
///    `tap_internal_key` on the PSBT input and stamp a witness-weight estimate so BDK accounts for
///    it in fee math.
/// 2. The target child fee rate is the rate that lifts the (parent, child) package to
///    `target_pkg_fee_rate`. We compute it from `parent_fee`, `parent.vbytes`, and a child vbytes
///    estimate. BDK then sizes the funding input + change to that rate.
///
/// Computing the child rate explicitly (rather than asking BDK for a "package rate") is the
/// only way that works without intrusive BDK changes; BDK doesn't know about the parent.
fn build_cpfp_child_impl(
    wallet: &mut Wallet,
    parent: &Transaction,
    parent_fee: Amount,
    anchor: AnchorInfo,
    target_pkg_fee_rate: FeeRate,
    exclude: &[OutPoint],
) -> Result<FundedPsbt, NativeGeneralError> {
    let anchor_vout = anchor.vout;
    let anchor_outpoint = OutPoint {
        txid: parent.compute_txid(),
        vout: anchor_vout,
    };
    let anchor_txout = parent
        .output
        .get(anchor_vout as usize)
        .ok_or(NativeGeneralError::AnchorVoutOutOfRange {
            vout: anchor_vout,
            parent_outputs: parent.output.len(),
        })?
        .clone();

    // ── Compute the child's target fee rate ─────────────────────────────────
    //
    // The package math:
    //   package_vbytes = parent.vbytes + child.vbytes
    //   target_pkg_fee = target_pkg_fee_rate * package_vbytes
    //   child_fee = target_pkg_fee - parent_fee
    //   child_fee_rate = child_fee / child.vbytes
    //
    // We don't know child.vbytes yet — it depends on which funding input BDK picks. Use a
    // representative estimate (one Taproot funding input + one Taproot change output + anchor
    // input + version+locktime+counts overhead). BDK will size to the resulting fee RATE, so
    // small estimate errors translate into ~per-vB rounding, not gross over- or under-payment.
    let parent_vbytes: u64 = parent
        .vsize()
        .try_into()
        .expect("tx.vsize() fits in u64 on every supported target");
    let child_vbytes_estimate = ESTIMATED_CHILD_VBYTES;
    let pkg_vbytes = parent_vbytes.saturating_add(child_vbytes_estimate);
    let target_pkg_fee_sat = target_pkg_fee_rate
        .to_sat_per_kwu()
        .saturating_mul(pkg_vbytes.saturating_mul(4))
        / 1000;
    let child_fee_sat = target_pkg_fee_sat.saturating_sub(parent_fee.to_sat());
    // The child must pay at least 1 sat/vB on its own vbytes (BIP-431 v3 policy treats
    // sub-1 sat/vB as nonstandard). If the parent already overpays the package target,
    // raise the child to its own floor anyway.
    let min_child_fee_sat = child_vbytes_estimate.max(1);
    let child_fee_sat = child_fee_sat.max(min_child_fee_sat);
    let child_fee_rate_sat_per_vb = child_fee_sat.div_ceil(child_vbytes_estimate);
    let child_fee_rate = FeeRate::from_sat_per_vb(child_fee_rate_sat_per_vb).unwrap_or_else(|| {
        // Only failure mode is FeeRate's internal sat/kwu overflowing u64, which requires
        // sat/vB > 7.4×10^16 — far beyond anything the fee math here can produce given a
        // bounded `target_pkg_fee_rate` and reasonable parent vbytes.
        FeeRate::from_sat_per_vb(1).expect("1 sat/vB is always a valid FeeRate")
    });

    // ── Build the child ─────────────────────────────────────────────────────

    let exclude_set: BTreeSet<OutPoint> = exclude.iter().copied().collect();
    // The anchor itself is foreign-injected, so make sure no auto-selector tries to use it
    // (defensive — the wallet shouldn't recognise it anyway, but if a future change marks
    // anchor-shaped outputs as wallet-spendable we want to keep this safe).
    let mut unspendable: Vec<OutPoint> = exclude_set.iter().copied().collect();
    unspendable.push(anchor_outpoint);

    // Build the foreign UTXO PSBT input for the anchor — witness_utxo + tap_internal_key, no
    // signature, no scripts. Caller signs downstream.
    let mut anchor_psbt_input = PsbtInput {
        witness_utxo: Some(anchor_txout.clone()),
        ..Default::default()
    };
    anchor_psbt_input.tap_internal_key = Some(anchor.internal_key);

    // The child has no external recipient: it's a self-spend that consolidates the anchor
    // value + selected funding back to the wallet (minus fee). Use `drain_to` to make this
    // explicit, otherwise BDK rejects with `NoRecipients`.
    let drain_script = wallet
        .peek_address(KeychainKind::External, 0)
        .address
        .script_pubkey();

    let mut tx_builder = wallet.build_tx();
    tx_builder.version(3);
    tx_builder.fee_rate(child_fee_rate);
    tx_builder.ordering(TxOrdering::Untouched);
    tx_builder.unspendable(unspendable);
    tx_builder
        .add_foreign_utxo(
            anchor_outpoint,
            anchor_psbt_input,
            bdk_wallet::bitcoin::Weight::from_wu(TAPROOT_KEY_PATH_SAT_WEIGHT as u64),
        )
        .map_err(|e| NativeGeneralError::AnchorForeignUtxo(format!("{e:?}")))?;
    tx_builder.drain_to(drain_script);
    // BDK adds the wallet's funding input + sizes the drain output to `child_fee_rate`.

    let psbt = tx_builder.finish()?;

    // Sanity check: the child fee rate was sized assuming `child.vbytes ≈
    // ESTIMATED_CHILD_VBYTES`. If BDK selected an unusual layout that pushes the unsigned
    // vbytes well above the estimate, the package will pay above target (mostly harmless) —
    // but log it so an unexpected drift surfaces in observability rather than silently
    // overpaying.
    let unsigned_vbytes: u64 = psbt
        .unsigned_tx
        .vsize()
        .try_into()
        .expect("psbt.unsigned_tx.vsize fits in u64 on every supported target");
    if unsigned_vbytes > ESTIMATED_CHILD_VBYTES {
        warn!(
            unsigned_vbytes,
            estimate = ESTIMATED_CHILD_VBYTES,
            "CPFP child unsigned vbytes exceed the ESTIMATED_CHILD_VBYTES margin; \
             package will pay slightly above target — not a correctness issue but indicates \
             a heavier-than-expected child layout"
        );
    }

    Ok(FundedPsbt { psbt })
}

/// Representative child vbytes used to compute the child fee rate from a package target.
///
/// Sized for the typical case: one Taproot key-path anchor input (~57.5 vB), one Taproot
/// key-path wallet funding input (~57.5 vB), one Taproot change output (~43 vB), plus
/// version / locktime / counts overhead (~10 vB) → ~168 vB. Round up to 180 for safety
/// margin against underestimating fees in unusual layouts (e.g. larger change scripts).
const ESTIMATED_CHILD_VBYTES: u64 = 180;

/// Builds a v3 (TRUC) PSBT using BDK's transaction builder, with `outputs` as recipients,
/// optional explicit input selection, the given fee rate, and `exclude` skipped during
/// auto-selection.
fn build_v3_psbt(
    wallet: &mut Wallet,
    outputs: &[TxOut],
    explicit_inputs: Option<&[OutPoint]>,
    fee_rate: FeeRate,
    exclude: &[OutPoint],
) -> Result<Psbt, CreateTxError> {
    let exclude_set: BTreeSet<OutPoint> = exclude.iter().copied().collect();

    let mut tx_builder = wallet.build_tx();
    tx_builder.version(3);
    tx_builder.fee_rate(fee_rate);
    tx_builder.ordering(TxOrdering::Untouched);

    match explicit_inputs {
        Some(inputs) => {
            for outpoint in inputs {
                tx_builder
                    .add_utxo(*outpoint)
                    .map_err(|_| CreateTxError::UnknownUtxo)?;
            }
            tx_builder.manually_selected_only();
        }
        None => {
            tx_builder.unspendable(exclude_set.into_iter().collect());
        }
    }

    for output in outputs {
        tx_builder.add_recipient(output.script_pubkey.clone(), output.value);
    }

    tx_builder.finish()
}

#[cfg(test)]
mod tests {
    use bdk_wallet::{
        bitcoin::{
            absolute, hashes::Hash, key::TapTweak, secp256k1::Secp256k1, transaction::Version,
            Address, Amount, OutPoint, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
        },
        test_utils::{get_funded_wallet_single, get_test_tr_single_sig},
    };

    use super::*;
    use crate::general::AnchorInfo;

    /// Constructs an XOnlyPublicKey from a deterministic non-zero scalar, for tests that need
    /// "some valid key, doesn't matter which".
    fn fake_anchor_key() -> XOnlyPublicKey {
        let bytes = [3u8; 32];
        let sk = bdk_wallet::bitcoin::secp256k1::SecretKey::from_slice(&bytes).unwrap();
        let secp = Secp256k1::new();
        let (xonly, _) = bdk_wallet::bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .x_only_public_key();
        xonly
    }

    /// Builds a synthetic "parent" tx whose `vout = anchor_vout` is a keyed-Taproot anchor
    /// at `anchor_value`. The rest of the outputs are dummies, so the parent looks like a
    /// real bridge tx that has an anchor at a known position.
    fn parent_with_anchor(
        anchor_internal_key: XOnlyPublicKey,
        anchor_vout: u32,
        anchor_value: Amount,
    ) -> Transaction {
        let secp = Secp256k1::new();
        let anchor_addr = Address::p2tr(&secp, anchor_internal_key, None, Network::Regtest);
        let anchor_txout = TxOut {
            value: anchor_value,
            script_pubkey: anchor_addr.script_pubkey(),
        };
        let mut outputs = Vec::new();
        let dummy_addr = Address::p2tr(&secp, fake_anchor_key(), None, Network::Regtest);
        for _ in 0..anchor_vout {
            outputs.push(TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: dummy_addr.script_pubkey(),
            });
        }
        outputs.push(anchor_txout);

        Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::all_zeros(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: outputs,
        }
    }

    #[tokio::test]
    async fn happy_path_emits_psbt_with_anchor_and_funding() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let anchor = AnchorInfo {
            vout: 0,
            internal_key: anchor_key,
        };

        let funded = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            FeeRate::from_sat_per_vb(10).unwrap(),
            &[],
        )
        .expect("happy-path build_cpfp_child must succeed");

        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };
        let psbt = &funded.psbt;

        // Anchor must be present as an input with witness_utxo + tap_internal_key, unsigned.
        let anchor_input_idx = psbt
            .unsigned_tx
            .input
            .iter()
            .position(|i| i.previous_output == anchor_outpoint)
            .expect("anchor outpoint must appear as an input");
        let anchor_psbt_input = &psbt.inputs[anchor_input_idx];
        assert!(anchor_psbt_input.witness_utxo.is_some());
        assert_eq!(anchor_psbt_input.tap_internal_key, Some(anchor_key));
        assert!(
            anchor_psbt_input.tap_key_sig.is_none(),
            "anchor must not be signed by the backend"
        );

        // At least one funding input must exist (the wallet's contribution).
        assert!(psbt.unsigned_tx.input.len() >= 2);

        // `spent()` (derived from psbt.unsigned_tx) includes EVERY input — including the
        // anchor. The caller is responsible for filtering anchor outpoints out of the lease
        // set when bookkeeping is anchor-aware (the OperatorWallet composer does that via
        // its release/lease cycle around build_cpfp_child).
        let spent = funded.spent();
        assert!(
            spent.contains(&anchor_outpoint),
            "spent() reports every input including the foreign anchor"
        );
        assert!(
            spent.iter().any(|op| *op != anchor_outpoint),
            "must report at least one wallet input as spent"
        );

        // The child must be v3.
        assert_eq!(psbt.unsigned_tx.version, Version(3));
    }

    #[tokio::test]
    async fn anchor_vout_out_of_range_errors() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        // Parent has 1 output (vout 0). Asking for anchor at vout 5 is out of range.
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let anchor = AnchorInfo {
            vout: 5,
            internal_key: anchor_key,
        };

        let err = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            FeeRate::from_sat_per_vb(10).unwrap(),
            &[],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            NativeGeneralError::AnchorVoutOutOfRange { vout: 5, .. }
        ));
    }

    #[tokio::test]
    async fn anchor_at_non_zero_vout_resolves_correctly() {
        let (mut wallet, _) = get_funded_wallet_single(get_test_tr_single_sig());
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 2, Amount::from_sat(330));
        let anchor = AnchorInfo {
            vout: 2,
            internal_key: anchor_key,
        };

        let funded = build_cpfp_child_impl(
            &mut wallet,
            &parent,
            Amount::from_sat(220),
            anchor,
            FeeRate::from_sat_per_vb(5).unwrap(),
            &[],
        )
        .expect("non-zero-vout anchor must work");

        let anchor_outpoint = OutPoint {
            txid: parent.compute_txid(),
            vout: 2,
        };
        assert!(funded
            .psbt
            .unsigned_tx
            .input
            .iter()
            .any(|i| i.previous_output == anchor_outpoint));
    }

    #[tokio::test]
    async fn taptweak_for_keyed_anchor_matches_constructed_script() {
        // Sanity check: the anchor script_pubkey we put into witness_utxo must encode the
        // same output key as what BIP-341 derives from the internal key with no script tree.
        // This protects against future drift between the way we construct the anchor and the
        // way BDK / rust-bitcoin tweak the internal key for signing.
        let anchor_key = fake_anchor_key();
        let parent = parent_with_anchor(anchor_key, 0, Amount::from_sat(330));
        let secp = Secp256k1::new();
        let (expected_output_key, _) = anchor_key.tap_tweak(&secp, None);
        let derived_script =
            Address::p2tr_tweaked(expected_output_key, Network::Regtest).script_pubkey();
        assert_eq!(parent.output[0].script_pubkey, derived_script);
    }
}
