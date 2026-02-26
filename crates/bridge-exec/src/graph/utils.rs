//! Common utilities for executors.

use algebra::predicate;
use bdk_wallet::Wallet;
use bitcoin::{
    Psbt, TapSighashType,
    hashes::Hash,
    sighash::{Prevouts, SighashCache},
    taproot,
};
use btc_tracker::{event::TxStatus, tx_driver::TxDriver};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::*;
use tracing::info;

use crate::errors::ExecutorError;

/// Finalizes and broadcasts a claim funding transaction.
///
/// This function assumes that the PSBT has already been funded. It will finalize this PSBT by
/// singing all inputs using the general wallet signer in the secret service, submit the
/// finalized transaction to the tx driver for broadcasting and then wait for the transaction to
/// appear in the mempool.
pub(super) async fn finalize_claim_funding_tx(
    s2_client: &SecretServiceClient,
    tx_driver: &TxDriver,
    general_wallet: &Wallet,
    psbt: Psbt,
) -> Result<(), ExecutorError> {
    let mut tx = psbt.unsigned_tx;
    let txins_as_outs = tx
        .input
        .iter()
        .map(|txin| {
            general_wallet
                .get_utxo(txin.previous_output)
                .expect("always have this output because the wallet selected it in the first place")
                .txout
        })
        .collect::<Vec<_>>();

    let mut sighasher = SighashCache::new(&mut tx);
    let sighash_type = TapSighashType::Default;
    let prevouts = Prevouts::All(&txins_as_outs);
    for input_index in 0..txins_as_outs.len() {
        let sighash = sighasher
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .expect("failed to construct sighash");
        let signature = s2_client
            .general_wallet_signer()
            .sign(&sighash.to_byte_array(), None)
            .await?;

        let signature = taproot::Signature {
            signature,
            sighash_type,
        };
        sighasher
            .witness_mut(input_index)
            .expect("an input here")
            .push(signature.to_vec());
    }

    let txid = tx.compute_txid();
    info!(%txid, "submitting claim funding tx to the tx driver");
    tx_driver
        .drive(tx, predicate::eq(TxStatus::Mempool)) // It's our tx, we won't double spend
        .await?;

    info!(%txid, "claim funding tx detected in mempool");

    Ok(())
}
