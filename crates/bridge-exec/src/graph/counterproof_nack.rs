//! Executor for the counterproof NACK transaction.

use bitcoin::{OutPoint, TxOut, hashes::Hash};
use btc_tracker::event::TxStatus;
use strata_bridge_primitives::{
    scripts::taproot::TaprootTweak,
    types::{DepositIdx, GameIndex, OperatorIdx},
};
use strata_bridge_tx_graph::{fee, transactions::prelude::CounterproofNackTx};
use strata_mosaic_client_api::types::{CompletedSignatures, Sighash, Tweak};
use tracing::{info, warn};

use crate::{
    chain::{self, CpfpKind, publish_signed_transaction},
    errors::ExecutorError,
    output_handles::OutputHandles,
};

/// Signs and publishes the counterproof NACK transaction to reject an invalid counterproof.
pub(super) async fn publish_counterproof_nack(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    game_index: GameIndex,
    counterprover_idx: OperatorIdx,
    completed_signatures: CompletedSignatures,
    mut counterproof_nack_tx: CounterproofNackTx,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %game_index, %counterprover_idx, "preparing counterproof nack");

    // Single output: forward the connector's dust value (minus the nack tx fee) back to the
    // operator's general wallet. The connector script is `minimal_non_dust` P2TR plus the
    // surcharge that funds this nack tx's fee, so the output still clears dust after the
    // subtraction.
    let connector_value = counterproof_nack_tx.prevouts()[0].value;
    let payout_value = connector_value - fee::counterproof_nack_fee();
    let payout_script = output_handles.wallet.read().await.general_script_pubkey();
    counterproof_nack_tx.push_output(TxOut {
        value: payout_value,
        script_pubkey: payout_script,
    });

    sign_and_broadcast_nack(
        output_handles,
        counterprover_idx,
        deposit_idx,
        game_index,
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
    game_index: GameIndex,
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

    info!(%deposit_idx, %game_index, %counterprover_idx, "calling mosaic evaluate_and_sign");
    let evaluate_and_sign_start = std::time::Instant::now();
    let wt_fault_signature = output_handles
        .mosaic_client
        .evaluate_and_sign(
            counterprover_idx,
            game_index,
            completed_signatures,
            sighash,
            tweak,
        )
        .await
        .map_err(|e| {
            warn!(%deposit_idx, %game_index, %counterprover_idx, ?e, "evaluate_and_sign failed");
            ExecutorError::MosaicErr(format!("evaluate_and_sign: {e:?}"))
        })?
        .ok_or_else(|| {
            ExecutorError::MosaicErr(
                "evaluator failed to extract fault secret from counterproof".into(),
            )
        })?;
    info!(
        %deposit_idx,
        %game_index,
        %counterprover_idx,
        elapsed = ?evaluate_and_sign_start.elapsed(),
        "mosaic evaluate_and_sign completed",
    );

    let signed_tx = nack_tx.finalize_partial(wt_fault_signature);

    info!(%deposit_idx, %game_index, %counterprover_idx, "publishing counterproof nack transaction");
    // Counterproof-nack has a single output: a P2TR to the operator's general wallet at
    // vout 0 (see the `push_output` call in `publish_counterproof_nack`). Use
    // ParentTxCombined so a CPFP child can spend that output under fee pressure.
    let payout_outpoint = OutPoint {
        txid: signed_tx.compute_txid(),
        vout: 0,
    };
    publish_signed_transaction(
        output_handles,
        &signed_tx,
        "counterproof nack",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(&signed_tx),
        CpfpKind::PayoutCombined { payout_outpoint },
    )
    .await
}
