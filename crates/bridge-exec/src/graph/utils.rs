//! Shared helpers for graph executors.

use algebra::predicate;
use bitcoin::{
    Psbt, TapSighashType, Witness,
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
/// This function assumes that the [`Psbt`] has already been funded with `witness_utxo`
/// populated on every input (which `OperatorWallet::create_reserved_utxos` guarantees by
/// returning a [`crate::Psbt`] whose inputs all carry the wallet's `witness_utxo`). It signs
/// all inputs via the caller-provided signer, submits the finalized transaction to the tx
/// driver for broadcasting, and waits for it to appear in the mempool.
pub(super) async fn finalize_claim_funding_tx(
    s2_client: &SecretServiceClient,
    tx_driver: &TxDriver,
    psbt: Psbt,
) -> Result<(), ExecutorError> {
    let txins_as_outs = psbt
        .inputs
        .iter()
        .map(|input| {
            input
                .witness_utxo
                .clone()
                .expect("PSBT input from claim-funding refill always has witness_utxo")
        })
        .collect::<Vec<_>>();
    // A "create-and-sign" backend (Fireblocks) returns the funding inputs already signed via
    // `final_script_witness`; capture those before moving the unsigned tx. Inputs without one are
    // the native descriptor-only backend's and get secret-service-signed below. Honouring this is
    // the `GeneralWallet` signing contract — skip what the backend already signed.
    let final_witnesses: Vec<Option<Witness>> = psbt
        .inputs
        .iter()
        .map(|input| input.final_script_witness.clone())
        .collect();
    let mut tx = psbt.unsigned_tx;

    let mut sighasher = SighashCache::new(&mut tx);
    let sighash_type = TapSighashType::Default;
    let prevouts = Prevouts::All(&txins_as_outs);
    for (input_index, final_witness) in final_witnesses.iter().enumerate() {
        if let Some(witness) = final_witness {
            *sighasher.witness_mut(input_index).expect("an input here") = witness.clone();
            continue;
        }
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
