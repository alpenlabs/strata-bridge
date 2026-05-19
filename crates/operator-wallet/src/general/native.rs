//! Native BDK-backed implementation of [`GeneralWallet`].
//!
//! The native wallet holds the operator's general-funds descriptor (`tr(general_pubkey)`) but
//! never holds private keys: signing is delegated to the secret-service by the caller. As a
//! consequence every PSBT returned by this impl carries `witness_utxo` and `tap_internal_key`
//! on its inputs but no signatures — the caller signs downstream.

use std::collections::BTreeSet;

use bdk_wallet::{
    bitcoin::{FeeRate, Network, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, XOnlyPublicKey},
    chain::ChainPosition,
    descriptor,
    error::CreateTxError,
    KeychainKind, TxOrdering, Wallet,
};
use thiserror::Error;
use tracing::info;

use crate::{
    general::{FundedPsbt, GeneralWallet, UtxoInfo},
    sync::{Backend, SyncError},
};

/// Native BDK-backed general wallet.
#[derive(Debug)]
pub struct NativeGeneralWallet {
    /// Cached at construction; the BDK descriptor doesn't change at runtime.
    script_pubkey: ScriptBuf,
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
    /// CPFP-child building is intentionally unimplemented until STR-3439 lands.
    #[error("native build_cpfp_child not yet implemented (STR-3439)")]
    CpfpChildNotImplemented,
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
        let spent = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();
        Ok(FundedPsbt { psbt, spent })
    }

    async fn build_cpfp_child(
        &mut self,
        _parent: &Transaction,
        _anchor_vout: u32,
        _target_pkg_fee_rate: FeeRate,
        _exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        // TODO(STR-3439): wire up CPFP child construction during the tx-driver / RBF work.
        Err(NativeGeneralError::CpfpChildNotImplemented)
    }
}

/// Converts a BDK [`bdk_wallet::LocalOutput`] into a backend-neutral [`UtxoInfo`], computing
/// confirmations against the wallet's current tip.
fn local_output_to_utxo_info(lo: &bdk_wallet::LocalOutput, tip_height: u32) -> UtxoInfo {
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
