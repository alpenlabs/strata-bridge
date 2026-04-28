//! Executor for the counterproof NACK transaction.

use bitcoin::{
    Amount, OutPoint, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    hashes::Hash,
    sighash::{Prevouts, SighashCache},
};
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_primitives::{
    scripts::{prelude::create_key_spend_hash, taproot::TaprootTweak},
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
    counter_prover_idx: OperatorIdx,
    counterproof_tx: Transaction,
    counterproof_nack_tx: CounterproofNackTx,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %counter_prover_idx, "preparing counterproof nack");

    let completed_signatures = decode_completed_sigs(&counterproof_tx)?;

    let AttachedFunding {
        nack_tx,
        funding_outpoint,
        prevouts,
    } = attach_operator_funding(output_handles, counterproof_nack_tx).await?;

    let result = sign_and_broadcast_nack(
        output_handles,
        counter_prover_idx,
        deposit_idx,
        completed_signatures,
        nack_tx,
        &prevouts,
    )
    .await;

    if result.is_err() {
        output_handles
            .wallet
            .write()
            .await
            .release_outpoints(&[funding_outpoint]);
    }
    result
}

/// Output of [`attach_operator_funding`]: the fully-populated NACK plus the leased funding
/// outpoint (so the caller can release on failure) and a snapshot of all prevouts (needed
/// because [`CounterproofNackTx::finalize_partial`] consumes the NACK by value).
struct AttachedFunding {
    nack_tx: CounterproofNackTx,
    funding_outpoint: OutPoint,
    prevouts: Vec<TxOut>,
}

/// Picks an operator-funded UTXO from the general wallet, leases it, and pushes a funding
/// input + change output onto the NACK template. Single wallet write-lock — no race window
/// between selection and the change-script lookup.
async fn attach_operator_funding(
    output_handles: &OutputHandles,
    mut nack_tx: CounterproofNackTx,
) -> Result<AttachedFunding, ExecutorError> {
    const NACK_FIXED_FEE: Amount = Amount::from_sat(1_000);
    const NACK_MIN_FUNDING_VALUE: Amount = Amount::from_sat(10_000);

    let (funding_outpoint, funding_prevout, change_script) = {
        let mut wallet = output_handles.wallet.write().await;
        if let Err(e) = wallet.sync().await {
            warn!(
                ?e,
                "could not sync wallet before nack funding selection; continuing"
            );
        }
        let selected = wallet
            .select_and_lease_general_utxo(|u| u.txout.value >= NACK_MIN_FUNDING_VALUE)
            .ok_or_else(|| {
                ExecutorError::WalletErr(format!(
                    "no general utxo >= {} sat for counterproof nack funding",
                    NACK_MIN_FUNDING_VALUE.to_sat()
                ))
            })?;
        let change_script = wallet.general_script_buf().clone();
        let outcome = (selected.outpoint, selected.txout, change_script);
        drop(wallet);
        outcome
    };

    let change_value = funding_prevout
        .value
        .checked_sub(NACK_FIXED_FEE)
        .ok_or_else(|| {
            ExecutorError::WalletErr(format!(
                "funding utxo value {} sat is below fixed nack fee {} sat",
                funding_prevout.value.to_sat(),
                NACK_FIXED_FEE.to_sat(),
            ))
        })?;

    nack_tx.push_input(
        TxIn {
            previous_output: funding_outpoint,
            sequence: Sequence::MAX,
            ..Default::default()
        },
        funding_prevout,
    );
    nack_tx.push_output(TxOut {
        value: change_value,
        script_pubkey: change_script,
    });

    let prevouts = nack_tx.prevouts().to_vec();
    Ok(AttachedFunding {
        nack_tx,
        funding_outpoint,
        prevouts,
    })
}

/// Has mosaic sign the connector input, signs the funding input via the operator's general
/// wallet, and broadcasts. The funding input is always the last one (`push_input` appends).
#[allow(clippy::large_types_passed_by_value)] // mosaic's evaluate_and_sign takes CompletedSignatures by value
async fn sign_and_broadcast_nack(
    output_handles: &OutputHandles,
    counter_prover_idx: OperatorIdx,
    deposit_idx: DepositIdx,
    completed_signatures: CompletedSignatures,
    nack_tx: CounterproofNackTx,
    prevouts: &[TxOut],
) -> Result<(), ExecutorError> {
    // Sighash + tap tweak for the connector input (key-path spend with `wt_i_fault` as the
    // internal key; script-path is impossible by construction).
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

    info!(%deposit_idx, %counter_prover_idx, "calling mosaic evaluate_and_sign");
    let wt_fault_signature = output_handles
        .mosaic_client
        .evaluate_and_sign(
            counter_prover_idx,
            deposit_idx,
            G16ProofRaw([0u8; N_WITHDRAWAL_INPUT_WIRES]),
            completed_signatures,
            sighash,
            tweak,
        )
        .await
        .map_err(|e| {
            warn!(%deposit_idx, %counter_prover_idx, ?e, "evaluate_and_sign failed");
            ExecutorError::MosaicErr(format!("evaluate_and_sign: {e:?}"))
        })?
        .ok_or_else(|| {
            ExecutorError::MosaicErr(
                "evaluator failed to extract fault secret from counterproof".into(),
            )
        })?;

    let mut signed_tx = nack_tx.finalize_partial(wt_fault_signature);

    // Invariant: at sign time the NACK has exactly 2 prevouts — the connector input
    // (index 0) and the funding input that `attach_operator_funding` appended (index 1).
    // Trip loudly in tests if a future change adds another input between attach and sign.
    debug_assert_eq!(
        prevouts.len(),
        2,
        "expected exactly 2 prevouts (connector + funding) at sign time"
    );
    // Funding input is always the last one (push_input appends). Derive the index from
    // the prevouts length rather than hardcoding `1`.
    let funding_input_index = prevouts.len() - 1;
    let mut sighash_cache = SighashCache::new(&signed_tx);
    let funding_sighash = create_key_spend_hash(
        &mut sighash_cache,
        Prevouts::All(prevouts),
        TapSighashType::Default,
        funding_input_index,
    )
    .map_err(|e| ExecutorError::WalletErr(format!("nack funding sighash: {e}")))?;

    let funding_signature = output_handles
        .s2_client
        .general_wallet_signer()
        .sign(funding_sighash.as_ref(), None)
        .await
        .map_err(ExecutorError::SecretServiceErr)?;

    signed_tx.input[funding_input_index]
        .witness
        .push(funding_signature.serialize());

    info!(%deposit_idx, %counter_prover_idx, "publishing counterproof nack transaction");
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

    let witness = &counterproof_tx.input[0].witness;
    if witness.len() != WANT {
        return Err(ExecutorError::InvalidTxStructure(format!(
            "counterproof witness has {} elements, expected {WANT}",
            witness.len(),
        )));
    }

    let sigs: [Signature; N] = std::array::from_fn(|i| {
        // operator_signatures were pushed `.rev()`, so undo that ordering.
        Signature::from_slice(&witness[N - 1 - i])
            .expect("on-chain counterproof signature must parse")
    });
    Ok(sigs)
}
