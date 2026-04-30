//! Executor for the counterproof NACK transaction.

use bitcoin::{Transaction, TxOut, hashes::Hash};
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use strata_bridge_primitives::{
    scripts::taproot::TaprootTweak,
    types::{DepositIdx, OperatorIdx},
};
use strata_bridge_tx_graph::transactions::prelude::CounterproofNackTx;
use strata_mosaic_client_api::types::{
    CompletedSignatures, G16ProofRaw, N_DEPOSIT_INPUT_WIRES, N_WITHDRAWAL_INPUT_WIRES, Sighash,
    Tweak,
};
use tracing::{info, warn};

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
};

/// Signs and publishes the counterproof NACK transaction to reject an invalid counterproof.
pub(super) async fn publish_counterproof_nack(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    counterprover_idx: OperatorIdx,
    counterproof_tx: Transaction,
    mut counterproof_nack_tx: CounterproofNackTx,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %counterprover_idx, "preparing counterproof nack");

    let completed_signatures = decode_completed_sigs(&counterproof_tx)?;

    // Single output: forward the connector's dust value back to the operator's general
    // wallet. The connector script is `minimal_non_dust` P2TR, so the output clears dust.
    let connector_value = counterproof_nack_tx.prevouts()[0].value;
    let payout_script = output_handles
        .wallet
        .read()
        .await
        .general_script_buf()
        .clone();
    counterproof_nack_tx.push_output(TxOut {
        value: connector_value,
        script_pubkey: payout_script,
    });

    sign_and_broadcast_nack(
        output_handles,
        counterprover_idx,
        deposit_idx,
        completed_signatures,
        counterproof_nack_tx,
    )
    .await
}

/// Asks mosaic for the connector signature, finalizes the tx, and broadcasts it.
async fn sign_and_broadcast_nack(
    output_handles: &OutputHandles,
    counterprover_idx: OperatorIdx,
    deposit_idx: DepositIdx,
    completed_signatures: CompletedSignatures,
    nack_tx: CounterproofNackTx,
) -> Result<(), ExecutorError> {
    // Key-path spend with `wt_i_fault` as the internal key; script-path is impossible by
    // construction.
    let signing_info = nack_tx.signing_info_partial();
    let sighash: Sighash = *signing_info.sighash.as_ref();
    let tweak: Option<Tweak> = match signing_info.tweak {
        TaprootTweak::Key { tweak } => tweak.map(Hash::to_byte_array),
        TaprootTweak::Script => {
            return Err(ExecutorError::InvalidTxStructure(
                "counterproof nack expected a key-path spend, got script".into(),
            ));
        }
    };

    info!(%deposit_idx, %counterprover_idx, "calling mosaic evaluate_and_sign");
    let evaluate_and_sign_start = std::time::Instant::now();
    let wt_fault_signature = output_handles
        .mosaic_client
        .evaluate_and_sign(
            counterprover_idx,
            deposit_idx,
            G16ProofRaw([0u8; N_WITHDRAWAL_INPUT_WIRES]),
            completed_signatures,
            sighash,
            tweak,
        )
        .await
        .map_err(|e| {
            warn!(%deposit_idx, %counterprover_idx, ?e, "evaluate_and_sign failed");
            ExecutorError::MosaicErr(format!("evaluate_and_sign: {e:?}"))
        })?
        .ok_or_else(|| {
            ExecutorError::MosaicErr(
                "evaluator failed to extract fault secret from counterproof".into(),
            )
        })?;
    info!(
        %deposit_idx,
        %counterprover_idx,
        elapsed_ms = evaluate_and_sign_start.elapsed().as_millis() as u64,
        "mosaic evaluate_and_sign completed",
    );

    let signed_tx = nack_tx.finalize_partial(wt_fault_signature);

    info!(%deposit_idx, %counterprover_idx, "publishing counterproof nack transaction");
    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "counterproof nack",
        TxStatus::is_buried,
    )
    .await
}

/// Decodes the operator signatures from input[0] of an on-chain Counterproof tx.
fn decode_completed_sigs(
    counterproof_tx: &Transaction,
) -> Result<CompletedSignatures, ExecutorError> {
    const N: usize = N_DEPOSIT_INPUT_WIRES + N_WITHDRAWAL_INPUT_WIRES;
    // `+ 3` accounts for the trailing n-of-n signature, leaf script, and control block
    // that follow the per-byte operator signatures in the counterproof witness.
    const WANT: usize = N + 3;

    let witness_len = counterproof_tx.input[0].witness.len();
    if witness_len != WANT {
        return Err(ExecutorError::InvalidTxStructure(format!(
            "counterproof witness has {witness_len} elements, expected {WANT}"
        )));
    }

    // The witness layout is `[sig_{N-1}, .., sig_0, n-of-n sig, leaf script, control
    // block]` — operator signatures pushed `.rev()`, then 3 trailing items. Reverse +
    // skip(3) recovers `[sig_0, .., sig_{N-1}]`.
    let mut items = counterproof_tx.input[0].witness.to_vec();
    items.reverse();
    let sigs: Vec<Signature> = items
        .into_iter()
        .skip(3)
        .map(|w| Signature::from_slice(&w).expect("on-chain counterproof signature must parse"))
        .collect();
    Ok(sigs.try_into().expect("witness length validated above"))
}
