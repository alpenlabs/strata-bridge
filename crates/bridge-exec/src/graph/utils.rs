//! Shared helpers for graph executors.

use bitcoin::{
    Psbt, TapSighashType, Transaction,
    hashes::Hash,
    sighash::{Prevouts, SighashCache},
    taproot,
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::*;

use crate::errors::ExecutorError;

/// Signs a claim funding transaction.
///
/// This function assumes that the [`Psbt`] has already been funded with `witness_utxo`
/// populated on every input (which `OperatorWallet::create_reserved_utxos` guarantees by
/// returning a [`crate::Psbt`] whose inputs all carry the wallet's `witness_utxo`). It signs
/// all inputs via the caller-provided signer and returns the finalized transaction without
/// submitting it to the tx driver.
pub(super) async fn sign_claim_funding_tx(
    s2_client: &SecretServiceClient,
    psbt: Psbt,
) -> Result<Transaction, ExecutorError> {
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
    let mut tx = psbt.unsigned_tx;

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

    Ok(tx)
}
